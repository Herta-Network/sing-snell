package snellv6

import (
	"io"
	"net"
	"sync"

	"github.com/metacubex/sing/common/buf"
	E "github.com/metacubex/sing/common/exceptions"
	M "github.com/metacubex/sing/common/metadata"
	N "github.com/metacubex/sing/common/network"
	snell "github.com/sagernet/sing-snell"
	"github.com/sagernet/sing-snell/internal/packetbatch"
	"github.com/sagernet/sing-snell/internal/reuse"
)

const (
	maxUDPRequestHeaderLen  = 1 + 1 + 255 + 2
	maxUDPResponseHeaderLen = 1 + 16 + 2
)

func (c *clientPacketConn) udpRequestAddrLen(destination M.Socksaddr) int {
	if destination.IsIP() {
		if destination.Unwrap().Addr.Is4() {
			return 1 + 1 + 4 + 2
		}
		return 1 + 1 + 16 + 2
	}
	return 1 + len(destination.Fqdn) + 2
}

type clientPacketConn struct {
	net.Conn
	packetWrites packetbatch.State
	client       *Client

	writeAccess sync.Mutex
	writer      reuse.RecordWriter

	readAccess sync.Mutex
	reader     reuse.RecordReader

	readWaitOptions N.ReadWaitOptions
}

func (c *clientPacketConn) writeRequest() error {
	c.writeAccess.Lock()
	defer c.writeAccess.Unlock()
	if c.writer != nil {
		return nil
	}
	requestPayload := snell.Request{Command: snell.CommandUDP, ClientID: c.client.userKey}
	request := buf.NewSize(requestPayload.Len())
	err := requestPayload.Write(request)
	if err != nil {
		request.Release()
		return err
	}
	writer, err := writeFirstRecord(packetbatch.StrictWriter{Writer: c.Conn}, c.client.mode, c.client.psk, c.client.profile, request.Bytes())
	request.Release()
	if err != nil {
		return E.Cause(err, "write udp request")
	}
	c.writer = writer
	return nil
}

func (c *clientPacketConn) readReply() (reuse.RecordReader, error) {
	c.readAccess.Lock()
	defer c.readAccess.Unlock()
	if c.reader != nil {
		return c.reader, nil
	}
	reader, record, err := readFirstRecord(c.Conn, c.client.mode, c.client.psk, c.client.profile, c.readWaitOptions)
	if err != nil {
		return nil, E.Cause(err, "read udp reply")
	}
	cached, err := reuse.ParseReply(record)
	if err != nil {
		return nil, err
	}
	reader.SetCache(cached)
	c.reader = reader
	return reader, nil
}

func (c *clientPacketConn) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	_, err := c.WritePacketBatchCount([]*buf.Buffer{buffer}, []M.Socksaddr{destination})
	return err
}
func (c *clientPacketConn) CreatePacketBatchWriter() (N.PacketBatchWriter, bool) { return c, true }
func (c *clientPacketConn) CreatePacketBatchWriterWithCount() (N.PacketBatchWriterWithCount, bool) {
	return c, true
}
func (c *clientPacketConn) WritePacketBatch(buffers []*buf.Buffer, destinations []M.Socksaddr) error {
	_, err := c.WritePacketBatchCount(buffers, destinations)
	return err
}
func (c *clientPacketConn) Close() error { return c.packetWrites.Close(c.Conn) }

func (c *clientPacketConn) ReadPacket(buffer *buf.Buffer) (M.Socksaddr, error) {
	reader, err := c.readReply()
	if err != nil {
		return M.Socksaddr{}, err
	}
	record, err := reader.NextRecord()
	if err != nil {
		return M.Socksaddr{}, err
	}
	destination, err := snell.ReadUDPResponseAddress(record)
	if err != nil {
		record.Release()
		return M.Socksaddr{}, err
	}
	if record.Len() > buffer.FreeLen() {
		record.Release()
		return M.Socksaddr{}, io.ErrShortBuffer
	}
	_, err = buffer.Write(record.Bytes())
	record.Release()
	if err != nil {
		return M.Socksaddr{}, err
	}
	return destination, nil
}

func (c *clientPacketConn) FrontHeadroom() int {
	switch c.client.mode {
	case ModeUnsafeRaw:
		return snell.HeaderPlainLen + maxUDPRequestHeaderLen
	case ModeUnshaped:
		return snell.HeaderCipherLen + maxUDPRequestHeaderLen
	default:
		return c.client.profile.recordPrefixMax + snell.HeaderCipherLen + c.client.profile.padMaxHeadroom + maxUDPRequestHeaderLen
	}
}

func (c *clientPacketConn) RearHeadroom() int {
	if c.client.mode == ModeUnsafeRaw {
		return 0
	}
	return snell.AEADTagLen
}

func (c *clientPacketConn) WriterMTU() int {
	return maxPayload - maxUDPRequestHeaderLen
}

func (c *clientPacketConn) Upstream() any {
	return c.Conn
}

func (c *clientPacketConn) InitializeReadWaiter(options N.ReadWaitOptions) (needCopy bool) {
	c.readAccess.Lock()
	defer c.readAccess.Unlock()
	c.readWaitOptions = options
	if c.reader != nil {
		c.reader.InitializeReadWaiter(options)
	}
	return false
}

func (c *clientPacketConn) WaitReadPacket() (*buf.Buffer, M.Socksaddr, error) {
	reader, err := c.readReply()
	if err != nil {
		return nil, M.Socksaddr{}, err
	}
	record, err := reader.WaitReadBuffer()
	if err != nil {
		return nil, M.Socksaddr{}, err
	}
	destination, err := snell.ReadUDPResponseAddress(record)
	if err != nil {
		record.Release()
		return nil, M.Socksaddr{}, err
	}
	return record, destination, nil
}

type serverPacketConn struct {
	net.Conn
	packetWrites    packetbatch.State
	service         *Service
	reader          reuse.RecordReader
	readWaitOptions N.ReadWaitOptions

	writeAccess sync.Mutex
	writer      reuse.RecordWriter
}

func (c *serverPacketConn) responseAddrLen(source M.Socksaddr) int {
	if source.Unwrap().Addr.Is4() {
		return 1 + 4 + 2
	}
	return 1 + 16 + 2
}

func (c *serverPacketConn) ReadPacket(buffer *buf.Buffer) (M.Socksaddr, error) {
	record, err := c.reader.NextRecord()
	if err != nil {
		return M.Socksaddr{}, err
	}
	command, err := record.ReadByte()
	if err != nil {
		record.Release()
		return M.Socksaddr{}, err
	}
	if command != snell.UDPCommandForward {
		record.Release()
		return M.Socksaddr{}, E.Extend(snell.ErrUnsupportedCommand, "udp ", command)
	}
	destination, err := snell.ReadUDPRequestAddress(record)
	if err != nil {
		record.Release()
		return M.Socksaddr{}, err
	}
	if record.Len() > buffer.FreeLen() {
		record.Release()
		return M.Socksaddr{}, io.ErrShortBuffer
	}
	_, err = buffer.Write(record.Bytes())
	record.Release()
	if err != nil {
		return M.Socksaddr{}, err
	}
	return destination, nil
}

func (c *serverPacketConn) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	_, err := c.WritePacketBatchCount([]*buf.Buffer{buffer}, []M.Socksaddr{destination})
	return err
}
func (c *serverPacketConn) CreatePacketBatchWriter() (N.PacketBatchWriter, bool) { return c, true }
func (c *serverPacketConn) CreatePacketBatchWriterWithCount() (N.PacketBatchWriterWithCount, bool) {
	return c, true
}
func (c *serverPacketConn) WritePacketBatch(buffers []*buf.Buffer, destinations []M.Socksaddr) error {
	_, err := c.WritePacketBatchCount(buffers, destinations)
	return err
}
func (c *serverPacketConn) Close() error { return c.packetWrites.Close(c.Conn) }

func (c *serverPacketConn) writeTunnelReply() error {
	reply := [1]byte{snell.ReplyTunnel}
	if c.writer != nil {
		_, err := c.writer.Write(reply[:])
		if err != nil {
			return E.Cause(err, "write udp reply")
		}
		return nil
	}
	writer, err := writeFirstRecord(packetbatch.StrictWriter{Writer: c.Conn}, c.service.mode, c.service.psk, c.service.profile, reply[:])
	if err != nil {
		return E.Cause(err, "write udp reply")
	}
	c.writer = writer
	return nil
}

func (c *serverPacketConn) FrontHeadroom() int {
	switch c.service.mode {
	case ModeUnsafeRaw:
		return snell.HeaderPlainLen + maxUDPResponseHeaderLen
	case ModeUnshaped:
		return snell.HeaderCipherLen + maxUDPResponseHeaderLen
	default:
		return c.service.profile.recordPrefixMax + snell.HeaderCipherLen + c.service.profile.padMaxHeadroom + maxUDPResponseHeaderLen
	}
}

func (c *serverPacketConn) RearHeadroom() int {
	if c.service.mode == ModeUnsafeRaw {
		return 0
	}
	return snell.AEADTagLen
}

func (c *serverPacketConn) WriterMTU() int {
	return maxPayload - maxUDPResponseHeaderLen
}

func (c *serverPacketConn) Upstream() any {
	return c.Conn
}

func (c *serverPacketConn) InitializeReadWaiter(options N.ReadWaitOptions) (needCopy bool) {
	c.readWaitOptions = options
	c.reader.InitializeReadWaiter(options)
	return false
}

func (c *serverPacketConn) WaitReadPacket() (*buf.Buffer, M.Socksaddr, error) {
	record, err := c.reader.WaitReadBuffer()
	if err != nil {
		return nil, M.Socksaddr{}, err
	}
	command, err := record.ReadByte()
	if err != nil {
		record.Release()
		return nil, M.Socksaddr{}, err
	}
	if command != snell.UDPCommandForward {
		record.Release()
		return nil, M.Socksaddr{}, E.Extend(snell.ErrUnsupportedCommand, "udp ", command)
	}
	destination, err := snell.ReadUDPRequestAddress(record)
	if err != nil {
		record.Release()
		return nil, M.Socksaddr{}, err
	}
	return record, destination, nil
}

var (
	_ N.PacketConn                   = (*clientPacketConn)(nil)
	_ N.PacketReadWaiter             = (*clientPacketConn)(nil)
	_ N.PacketBatchWriteCreator      = (*clientPacketConn)(nil)
	_ N.WriterWithMTU                = (*clientPacketConn)(nil)
	_ N.PacketBatchWriter            = (*clientPacketConn)(nil)
	_ N.PacketBatchWriteCountCreator = (*clientPacketConn)(nil)
	_ N.PacketBatchWriterWithCount   = (*clientPacketConn)(nil)
	_ N.PacketConn                   = (*serverPacketConn)(nil)
	_ N.PacketReadWaiter             = (*serverPacketConn)(nil)
	_ N.PacketBatchWriteCreator      = (*serverPacketConn)(nil)
	_ N.WriterWithMTU                = (*serverPacketConn)(nil)
	_ N.PacketBatchWriter            = (*serverPacketConn)(nil)
	_ N.PacketBatchWriteCountCreator = (*serverPacketConn)(nil)
	_ N.PacketBatchWriterWithCount   = (*serverPacketConn)(nil)
)
