package snellv5

import (
	"crypto/rand"
	"encoding/binary"
	"io"
	"net"
	"net/netip"
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
	maxUDPResponseHeaderLen = 1 + 16 + 2
	minUDPPayloadLimit      = framePayloadStep
)

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
	destination, err := c.readRequestPacketDestination(record)
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

func (c *serverPacketConn) readRequestPacketDestination(record *buf.Buffer) (M.Socksaddr, error) {
	first, err := record.ReadByte()
	if err != nil {
		return M.Socksaddr{}, err
	}
	if first != 0x00 {
		var host []byte
		host, err = record.ReadBytes(int(first))
		if err != nil {
			return M.Socksaddr{}, err
		}
		var portBytes []byte
		portBytes, err = record.ReadBytes(2)
		if err != nil {
			return M.Socksaddr{}, err
		}
		return M.ParseSocksaddrHostPort(string(host), binary.BigEndian.Uint16(portBytes)), nil
	}
	addressFamily, err := record.ReadByte()
	if err != nil {
		return M.Socksaddr{}, err
	}
	switch addressFamily {
	case snell.AddressTypeIPv4:
		var addressBytes []byte
		addressBytes, err = record.ReadBytes(4)
		if err != nil {
			return M.Socksaddr{}, err
		}
		var portBytes []byte
		portBytes, err = record.ReadBytes(2)
		if err != nil {
			return M.Socksaddr{}, err
		}
		var address [4]byte
		copy(address[:], addressBytes)
		return M.SocksaddrFrom(netip.AddrFrom4(address), binary.BigEndian.Uint16(portBytes)), nil
	case snell.AddressTypeIPv6:
		var addressBytes []byte
		addressBytes, err = record.ReadBytes(16)
		if err != nil {
			return M.Socksaddr{}, err
		}
		var portBytes []byte
		portBytes, err = record.ReadBytes(2)
		if err != nil {
			return M.Socksaddr{}, err
		}
		var address [16]byte
		copy(address[:], addressBytes)
		return M.SocksaddrFrom(netip.AddrFrom16(address), binary.BigEndian.Uint16(portBytes)).Unwrap(), nil
	default:
		// snell-server v5.0.1: FUN_00140a50 consumes the 0x00 marker and the
		// unknown address-family byte, then forwards the rest as payload with an
		// empty destination instead of aborting the UDP tunnel.
		return M.Socksaddr{}, nil
	}
}

func (c *serverPacketConn) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	c.packetWrites.Access.Lock()
	defer c.packetWrites.Access.Unlock()
	buffers, destinations := []*buf.Buffer{buffer}, []M.Socksaddr{destination}
	_, err := c.writePacketBatchCount(buffers, destinations)
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
	salt := make([]byte, snell.SaltLen)
	_, err := io.ReadFull(rand.Reader, salt)
	if err != nil {
		return err
	}
	key := snell.DeriveKey(c.service.psk, salt)
	aead, err := snell.NewAEAD(key)
	if err != nil {
		return err
	}
	nonce := make([]byte, snell.NonceLen)
	recordWriter, err := newWriter(packetbatch.StrictWriter{Writer: c.Conn}, aead, nonce)
	if err != nil {
		return err
	}
	err = recordWriter.WriteFirst(salt, reply[:])
	if err != nil {
		return E.Cause(err, "write udp reply")
	}
	c.writer = recordWriter
	return nil
}

func (c *serverPacketConn) FrontHeadroom() int {
	return snell.HeaderCipherLen + maxUDPResponseHeaderLen
}

func (c *serverPacketConn) RearHeadroom() int {
	return snell.AEADTagLen
}

func (c *serverPacketConn) WriterMTU() int {
	return minUDPPayloadLimit - maxUDPResponseHeaderLen
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
	destination, err := c.readRequestPacketDestination(record)
	if err != nil {
		record.Release()
		return nil, M.Socksaddr{}, err
	}
	return record, destination, nil
}

var (
	_ N.PacketConn                   = (*serverPacketConn)(nil)
	_ N.PacketReadWaiter             = (*serverPacketConn)(nil)
	_ N.PacketBatchWriteCreator      = (*serverPacketConn)(nil)
	_ N.WriterWithMTU                = (*serverPacketConn)(nil)
	_ N.PacketBatchWriter            = (*serverPacketConn)(nil)
	_ N.PacketBatchWriteCountCreator = (*serverPacketConn)(nil)
	_ N.PacketBatchWriterWithCount   = (*serverPacketConn)(nil)
)
