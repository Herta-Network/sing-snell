package snellv5

import (
	"errors"
	"os"

	"github.com/metacubex/sing/common/buf"
	M "github.com/metacubex/sing/common/metadata"
	N "github.com/metacubex/sing/common/network"
	snell "github.com/sagernet/sing-snell"
	"github.com/sagernet/sing-snell/internal/packetbatch"
)

func (c *serverPacketConn) WritePacketBatchCount(buffers []*buf.Buffer, destinations []M.Socksaddr) (written int, err error) {
	c.packetWrites.Access.Lock()
	defer c.packetWrites.Access.Unlock()
	return c.writePacketBatchCount(buffers, destinations)
}

func (c *serverPacketConn) writePacketBatchCount(buffers []*buf.Buffer, destinations []M.Socksaddr) (written int, err error) {
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
		err := snell.WriteUDPResponseAddress(header, destination)
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
	c.writeAccess.Lock()
	if c.writer == nil {
		if err := c.writeTunnelReply(); err != nil {
			c.writeAccess.Unlock()
			buf.ReleaseMulti(buffers)
			return 0, c.packetWrites.Fail(c.Conn, err)
		}
	}
	c.writeAccess.Unlock()
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
