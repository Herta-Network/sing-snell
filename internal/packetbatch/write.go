// Package packetbatch preserves packet boundaries through encrypted stream writes.
package packetbatch

import (
	"io"
	"net"
	"sync"
	"sync/atomic"

	"github.com/metacubex/sing/common/buf"
	"github.com/metacubex/sing/common/bufio"
	N "github.com/metacubex/sing/common/network"
)

const MaxPackets = 64

// State serializes all packet writes, including legacy scalar and batch calls.
// Close never waits for Access: closing the transport must interrupt blocked I/O.
type State struct {
	Access   sync.Mutex
	Err      error // protected by Access
	closed   atomic.Bool
	once     sync.Once
	closeErr error
}

func (s *State) Check() error {
	if s.Err != nil {
		return s.Err
	}
	if s.closed.Load() {
		return net.ErrClosed
	}
	return nil
}
func (s *State) Close(conn net.Conn) error {
	s.closed.Store(true)
	s.once.Do(func() { s.closeErr = conn.Close() })
	return s.closeErr
}
func (s *State) Fail(conn net.Conn, err error) error {
	s.Err = err
	_ = s.Close(conn)
	return err
}

// StrictWriter catches a short handshake write even if the record encoder only
// propagates an error. It preserves the caller's protocol writer.
type StrictWriter struct{ io.Writer }

func (w StrictWriter) Write(p []byte) (int, error) {
	n, err := w.Writer.Write(p)
	if n < 0 || n > len(p) {
		return 0, io.ErrShortWrite
	}
	if n != len(p) && err == nil {
		err = io.ErrShortWrite
	}
	return n, err
}

// Sink receives exactly one already-encoded record per UDP packet. In
// particular, an empty UDP payload still has its address and command header.
type Sink struct {
	Writer  N.VectorisedWriterWithCount
	Written int
	Called  bool
}

func NewSink(writer io.Writer) *Sink {
	return &Sink{Writer: bufio.NewVectorisedWriterWithCount(writer)}
}
func (s *Sink) WriteVectorised(records []*buf.Buffer) error {
	s.Called = true
	if len(records) > MaxPackets {
		buf.ReleaseMulti(records)
		return io.ErrShortWrite
	}
	var ends [MaxPackets]int64
	var total int64
	for i, record := range records {
		total += int64(record.Len())
		ends[i] = total
	}
	n, err := s.Writer.WriteVectorisedCount(records)
	if n < 0 || n > total {
		n, err = 0, io.ErrShortWrite
	} else if n != total && err == nil {
		err = io.ErrShortWrite
	}
	for _, end := range ends[:len(records)] {
		if end > n {
			break
		}
		s.Written++
	}
	return err
}
