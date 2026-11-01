package packetbatch

import (
	"errors"
	"io"
	"testing"

	"github.com/metacubex/sing/common/buf"
	N "github.com/metacubex/sing/common/network"
)

type recordSource struct {
	upstream N.VectorisedWriter
	reject   bool
}

func (w *recordSource) CreatePacketVectorisedWriterFor(upstream N.VectorisedWriter) N.VectorisedWriter {
	w.upstream = upstream
	return w
}
func (w *recordSource) WriteVectorised(buffers []*buf.Buffer) error {
	if w.reject {
		buf.ReleaseMulti(buffers)
		return io.ErrShortBuffer
	}
	return w.upstream.WriteVectorised(buffers)
}

type discardWriter struct{}

func (discardWriter) Write(p []byte) (int, error) { return len(p), nil }

func TestStateEncodingProgressDoesNotCarryAcrossBatches(t *testing.T) {
	var state State
	source := &recordSource{}
	for _, reject := range []bool{false, true, false} {
		source.reject = reject
		buffers := []*buf.Buffer{buf.NewSize(1), buf.NewSize(1)}
		for _, b := range buffers {
			b.WriteByte(1)
		}
		n, called, err := state.Encode(discardWriter{}, source, buffers)
		if reject {
			if n != 0 || called || !errors.Is(err, io.ErrShortBuffer) {
				t.Fatalf("rejected batch inherited earlier write: n=%d called=%v err=%v", n, called, err)
			}
		} else if n != 2 || !called || err != nil {
			t.Fatalf("n=%d called=%v err=%v", n, called, err)
		}
		for _, b := range buffers {
			if b.RawCap() != 0 {
				t.Fatal("consumed buffer retained")
			}
		}
	}
}
