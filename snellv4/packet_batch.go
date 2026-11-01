package snellv4

import (
	"errors"
	"os"

	"github.com/metacubex/sing/common/buf"
	M "github.com/metacubex/sing/common/metadata"
	N "github.com/metacubex/sing/common/network"
	snell "github.com/sagernet/sing-snell"
	"github.com/sagernet/sing-snell/internal/packetbatch"
)

func (c *clientPacketConn) WritePacketBatchCount(buffers []*buf.Buffer, destinations []M.Socksaddr) (written int, err error) {
	c.packetWrites.Access.Lock()
	defer c.packetWrites.Access.Unlock()
	return c.writePacketBatchCount(buffers, destinations)
}

func (c *clientPacketConn) writePacketBatchCount(buffers []*buf.Buffer, destinations []M.Socksaddr) (written int, err error) {
	if err = c.packetWrites.Check(); err != nil {
		buf.ReleaseMulti(buffers)
		return 0, err
	}
	if len(buffers) == 0 || len(buffers) != len(destinations) {
		buf.ReleaseMulti(buffers)
		return 0, os.ErrInvalid
	}
	options := N.ReadWaitOptions{FrontHeadroom: c.FrontHeadroom(), RearHeadroom: c.RearHeadroom()}
	for i, destination := range destinations {
		if buffers[i] == nil {
			buf.ReleaseMulti(buffers)
			return 0, os.ErrInvalid
		}
		header := c.packetWrites.Header()
		_ = header.WriteByte(snell.UDPCommandForward)
		err := snell.WriteUDPRequestAddress(header, destination)
		if err != nil {
			buf.ReleaseMulti(buffers)
			return 0, err
		}
		if header.Len()+buffers[i].Len() > maxPayload {
			buf.ReleaseMulti(buffers)
			return 0, snell.ErrPayloadTooLarge
		}
		buffers[i] = options.Copy(buffers[i])
		copy(buffers[i].ExtendHeader(header.Len()), header.Bytes())
	}
	if err := c.writeRequest(); err != nil {
		buf.ReleaseMulti(buffers)
		return 0, c.packetWrites.Fail(c.Conn, err)
	}
	if _, err := c.readReply(); err != nil {
		buf.ReleaseMulti(buffers)
		return 0, c.packetWrites.Fail(c.Conn, err)
	}
	for start := 0; start < len(buffers); {
		if err = c.packetWrites.Check(); err != nil {
			buf.ReleaseMulti(buffers[start:])
			return written, err
		}
		end := min(start+packetbatch.MaxPackets, len(buffers))
		n, called, encodeErr := c.packetWrites.Encode(c.Conn, c.writer, buffers[start:end])
		err = encodeErr
		written += n
		if err != nil {
			buf.ReleaseMulti(buffers[end:])
			// Payload-window rejection is checked before consuming a nonce. Other
			// failures may leave an encrypted prefix on the wire or advance state.
			if called || !errors.Is(err, snell.ErrPayloadTooLarge) {
				err = c.packetWrites.Fail(c.Conn, err)
			}
			return written, err
		}
		start = end
	}
	return written, nil
}
