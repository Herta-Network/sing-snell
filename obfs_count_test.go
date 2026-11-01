package snell

import (
	"errors"
	"io"
	"net"
	"testing"
)

type obfsShortConn struct {
	net.Conn
	limit   int
	closed  bool
	wire    []byte
	failure error
}

func (c *obfsShortConn) Write(p []byte) (int, error) {
	c.wire = append([]byte(nil), p...)
	return min(c.limit, len(p)), c.failure
}
func (c *obfsShortConn) Close() error { c.closed = true; return nil }
func TestTLSObfsReportsPayloadProgress(t *testing.T) {
	size := tlsObfsRecordPayloadLen + 10
	for _, server := range []bool{false, true} {
		for _, limit := range []int{0, 4, 5, 6, 5 + tlsObfsRecordPayloadLen, 10 + tlsObfsRecordPayloadLen + 3, size + 10} {
			raw := &obfsShortConn{limit: limit}
			var writer io.Writer
			if server {
				writer = &tlsObfsServerConn{tlsObfsRecords: tlsObfsRecords{Conn: raw}, serverHelloSent: true}
			} else {
				writer = &tlsObfsClientConn{tlsObfsRecords: tlsObfsRecords{Conn: raw}, clientHelloSent: true}
			}
			n, err := writer.Write(make([]byte, size))
			want := max(0, min(tlsObfsRecordPayloadLen, limit-5)) + max(0, min(10, limit-10-tlsObfsRecordPayloadLen))
			if n != want {
				t.Fatalf("wire=%d payload=%d want=%d", limit, n, want)
			}
			if limit < size+10 {
				if !errors.Is(err, io.ErrShortWrite) || !raw.closed {
					t.Fatal("partial obfs record accepted")
				}
			} else if err != nil {
				t.Fatal(err)
			}
		}
	}
}
func TestObfsHandshakeRejectsShortSuccess(t *testing.T) {
	for _, mode := range []ObfsMode{ObfsModeHTTP, ObfsModeTLS} {
		for _, server := range []bool{false, true} {
			raw := &obfsShortConn{limit: 1}
			config := ObfsConfig{Mode: mode}
			var conn net.Conn
			if server {
				conn = config.ServerConn(raw)
			} else {
				conn = config.ClientConn(raw)
			}
			_, err := conn.Write([]byte("handshake"))
			if !errors.Is(err, io.ErrShortWrite) || !raw.closed {
				t.Fatalf("mode=%v server=%v err=%v", mode, server, err)
			}
		}
	}
}
