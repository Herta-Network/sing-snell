package snell_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metacubex/sing/common/buf"
	"github.com/metacubex/sing/common/bufio"
	M "github.com/metacubex/sing/common/metadata"
	N "github.com/metacubex/sing/common/network"
	snell "github.com/sagernet/sing-snell"
	"github.com/sagernet/sing-snell/snellv4"
	"github.com/sagernet/sing-snell/snellv5"
	"github.com/sagernet/sing-snell/snellv6"
)

const batchPSK = "snell-counted-batch-test-secret"

type packetCase struct {
	name string
	mode snellv6.Mode
	v6   bool
	obfs snell.ObfsMode
}

var packetCases = []packetCase{
	{name: "v4-v5"}, {name: "v4-v5-http", obfs: snell.ObfsModeHTTP}, {name: "v4-v5-tls", obfs: snell.ObfsModeTLS},
	{name: "v6-raw", v6: true, mode: snellv6.ModeUnsafeRaw},
	{name: "v6-unshaped", v6: true, mode: snellv6.ModeUnshaped},
	{name: "v6-shaped", v6: true, mode: snellv6.ModeDefault},
}

type packetEchoHandler struct {
	t    *testing.T
	echo bool
	seen chan string
	done chan struct{}
}

func (h *packetEchoHandler) NewConnectionEx(_ context.Context, c net.Conn, _, _ M.Socksaddr, _ N.CloseHandlerFunc) {
	c.Close()
	h.t.Error("unexpected TCP handler")
}
func (h *packetEchoHandler) NewPacketConnectionEx(_ context.Context, c N.PacketConn, _, _ M.Socksaddr, closeHandler N.CloseHandlerFunc) {
	defer close(h.done)
	defer c.Close()
	writer, ok := bufio.CreatePacketBatchWriterWithCount(c)
	if !ok {
		h.t.Error("server counted batch capability lost")
		return
	}
	var pending []*buf.Buffer
	var destinations []M.Socksaddr
	defer func() { buf.ReleaseMulti(pending) }()
	for {
		b := buf.NewSize(65535)
		dest, err := c.ReadPacket(b)
		if err != nil {
			b.Release()
			if closeHandler != nil {
				closeHandler(err)
			}
			return
		}
		h.seen <- string(b.Bytes())
		if !h.echo {
			b.Release()
			continue
		}
		pending = append(pending, b)
		destinations = append(destinations, dest)
		if len(pending) == 4 {
			n, err := writer.WritePacketBatchCount(pending, destinations)
			pending = nil
			destinations = nil
			if err != nil {
				h.t.Errorf("server batch: %v", err)
				return
			}
			if n != 4 {
				h.t.Errorf("server prefix=%d", n)
				return
			}
		}
	}
}
func startPacketPair(t *testing.T, tc packetCase, echo bool, wrap func(net.Conn) net.Conn) (N.NetPacketConn, *packetEchoHandler) {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	handler := &packetEchoHandler{t: t, echo: echo, seen: make(chan string, 128), done: make(chan struct{})}
	var service snell.Service
	var client snell.Method
	if tc.v6 {
		service, err = snellv6.NewService(snellv6.ServerOptions{PSK: []byte(batchPSK), Mode: tc.mode, Handler: handler})
		if err == nil {
			client, err = snellv6.NewClient(snellv6.ClientOptions{PSK: []byte(batchPSK), Mode: tc.mode})
		}
	} else {
		service, err = snellv5.NewService(snellv5.ServiceOptions{PSK: []byte(batchPSK), ObfsMode: tc.obfs, Handler: handler})
		if err == nil {
			client, err = snellv4.NewClient(snellv4.ClientOptions{PSK: []byte(batchPSK), ObfsMode: tc.obfs})
		}
	}
	if err != nil {
		t.Fatal(err)
	}
	if closer, ok := client.(interface{ Close() error }); ok {
		t.Cleanup(func() { closer.Close() })
	}
	go func() {
		c, err := listener.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(5 * time.Second))
		_ = service.NewConnection(context.Background(), c, M.SocksaddrFromNet(c.RemoteAddr()), nil)
	}()
	socket, err := net.Dial("tcp4", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	socket.SetDeadline(time.Now().Add(5 * time.Second))
	if wrap != nil {
		socket = wrap(socket)
	}
	conn, err := client.DialPacketConn(socket)
	if err != nil {
		socket.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	return conn, handler
}
func packetInputs(payloads ...string) ([]*buf.Buffer, []M.Socksaddr) {
	buffers := make([]*buf.Buffer, len(payloads))
	destinations := make([]M.Socksaddr, len(payloads))
	for i, p := range payloads {
		buffers[i] = buf.NewSize(len(p))
		buffers[i].WriteString(p)
		destinations[i] = M.ParseSocksaddr("127.0.0.1:53")
		if i%2 != 0 {
			destinations[i] = M.ParseSocksaddr("[::1]:5353")
		}
	}
	return buffers, destinations
}
func assertReleased(t *testing.T, buffers []*buf.Buffer) {
	t.Helper()
	for _, b := range buffers {
		if b.RawCap() != 0 {
			t.Fatal("batch retained owned payload")
		}
	}
}
func readEchoes(t *testing.T, conn N.NetPacketConn, payloads []string, destinations []M.Socksaddr) {
	t.Helper()
	for i, p := range payloads {
		b := make([]byte, 65535)
		n, addr, err := conn.ReadFrom(b)
		if err != nil {
			t.Fatal(err)
		}
		if string(b[:n]) != p || addr.String() != destinations[i].String() {
			t.Fatalf("echo %d size=%d source=%v", i, n, addr)
		}
	}
}
func TestPacketBatchCountLoopback(t *testing.T) {
	for _, tc := range packetCases {
		t.Run(tc.name, func(t *testing.T) {
			conn, _ := startPacketPair(t, tc, true, nil)
			writer, ok := bufio.CreatePacketBatchWriterWithCount(conn)
			if !ok {
				t.Fatal("client count capability lost")
			}
			payloads := []string{"", "one", string(bytes.Repeat([]byte("x"), 1200)), "tail"}
			if tc.v6 {
				payloads[3] = string(bytes.Repeat([]byte("y"), 60000))
			}
			buffers, destinations := packetInputs(payloads...)
			n, err := writer.WritePacketBatchCount(buffers, destinations)
			if err != nil || n != 4 {
				t.Fatalf("prefix=%d err=%v", n, err)
			}
			assertReleased(t, buffers)
			readEchoes(t, conn, payloads, destinations)
		})
	}
}

type partialPacketWire struct {
	net.Conn
	prefix int
	short  bool
	calls  atomic.Int32
}

func (c *partialPacketWire) WriteVectorisedCount(records []*buf.Buffer) (int64, error) {
	defer buf.ReleaseMulti(records)
	c.calls.Add(1)
	var wire []byte
	for _, b := range records[:c.prefix] {
		wire = append(wire, b.Bytes()...)
	}
	if c.prefix < len(records) {
		wire = append(wire, records[c.prefix].Bytes()[:1]...)
	}
	n, err := c.Conn.Write(wire)
	if err != nil {
		return int64(n), err
	}
	if c.short {
		return int64(n), nil
	}
	return int64(n), io.ErrClosedPipe
}
func TestPacketBatchCountFailurePoisonsAllWriters(t *testing.T) {
	for _, tc := range []packetCase{packetCases[0], packetCases[3], packetCases[4], packetCases[5]} {
		for _, prefix := range []int{0, 1, 3} {
			for _, short := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/%d/short=%v", tc.name, prefix, short), func(t *testing.T) {
					var wire *partialPacketWire
					conn, _ := startPacketPair(t, tc, false, func(c net.Conn) net.Conn {
						wire = &partialPacketWire{Conn: c, prefix: prefix, short: short}
						return wire
					})
					writer, ok := bufio.CreatePacketBatchWriterWithCount(conn)
					if !ok {
						t.Fatal("missing count writer")
					}
					buffers, destinations := packetInputs("", "one", "two")
					n, err := writer.WritePacketBatchCount(buffers, destinations)
					wantErr := error(io.ErrClosedPipe)
					if short && prefix < 3 {
						wantErr = io.ErrShortWrite
					}
					if short && prefix == 3 {
						if n != 3 || err != nil {
							t.Fatalf("n=%d err=%v", n, err)
						}
						return
					}
					if n != prefix || !errors.Is(err, wantErr) {
						t.Fatalf("n=%d err=%v", n, err)
					}
					assertReleased(t, buffers)
					second, _ := bufio.CreatePacketBatchWriterWithCount(conn)
					retry, targets := packetInputs("retry")
					n, err = second.WritePacketBatchCount(retry, targets)
					if n != 0 || err == nil || wire.calls.Load() != 1 {
						t.Fatal("retried failed cipher stream")
					}
					assertReleased(t, retry)
					if _, err = conn.WriteTo([]byte("scalar"), destinations[0].UDPAddr()); err == nil || wire.calls.Load() != 1 {
						t.Fatal("scalar write bypassed poisoned state")
					}
				})
			}
		}
	}
}
func TestPacketBatchValidationKeepsNonceAligned(t *testing.T) {
	for _, tc := range packetCases {
		t.Run(tc.name, func(t *testing.T) {
			conn, _ := startPacketPair(t, tc, true, nil)
			writer, _ := bufio.CreatePacketBatchWriterWithCount(conn)
			buffers, dests := packetInputs("small", string(bytes.Repeat([]byte("x"), 10000)))
			if tc.v6 {
				dests[1] = M.Socksaddr{}
			}
			n, err := writer.WritePacketBatchCount(buffers, dests)
			if n != 0 || err == nil {
				t.Fatalf("invalid batch: n=%d err=%v", n, err)
			}
			assertReleased(t, buffers)
			payloads := []string{"", "valid", "after", "rejection"}
			buffers, dests = packetInputs(payloads...)
			n, err = writer.WritePacketBatchCount(buffers, dests)
			if err != nil || n != 4 {
				t.Fatalf("stream invalidated: n=%d err=%v", n, err)
			}
			readEchoes(t, conn, payloads, dests)
		})
	}
}
func TestPacketBatchConcurrentScalarAndBatch(t *testing.T) {
	conn, handler := startPacketPair(t, packetCases[0], false, nil)
	var workers sync.WaitGroup
	for i := 0; i < 8; i++ {
		workers.Add(1)
		go func(i int) {
			defer workers.Done()
			p := fmt.Sprint(i)
			if i%2 == 0 {
				_, err := conn.WriteTo([]byte(p), M.ParseSocksaddr("127.0.0.1:53").UDPAddr())
				if err != nil {
					t.Error(err)
				}
			} else {
				writer, _ := bufio.CreatePacketBatchWriterWithCount(conn)
				bs, ds := packetInputs(p, p)
				n, err := writer.WritePacketBatchCount(bs, ds)
				if err != nil || n != 2 {
					t.Errorf("n=%d err=%v", n, err)
				}
			}
		}(i)
	}
	workers.Wait()
	for i := 0; i < 12; i++ {
		select {
		case <-handler.seen:
		case <-time.After(3 * time.Second):
			t.Fatal("concurrent packet lost")
		}
	}
}

type blockedPacketWire struct {
	net.Conn
	started chan struct{}
	closed  chan struct{}
	once    sync.Once
}

func (c *blockedPacketWire) WriteVectorisedCount(records []*buf.Buffer) (int64, error) {
	defer buf.ReleaseMulti(records)
	close(c.started)
	<-c.closed
	return 0, net.ErrClosed
}
func (c *blockedPacketWire) Close() error {
	c.once.Do(func() { close(c.closed) })
	return c.Conn.Close()
}
func TestPacketBatchCloseUnblocksWriter(t *testing.T) {
	for _, tc := range []packetCase{packetCases[0], packetCases[3], packetCases[4], packetCases[5]} {
		t.Run(tc.name, func(t *testing.T) {
			var wire *blockedPacketWire
			conn, _ := startPacketPair(t, tc, false, func(c net.Conn) net.Conn {
				wire = &blockedPacketWire{Conn: c, started: make(chan struct{}), closed: make(chan struct{})}
				return wire
			})
			writer, _ := bufio.CreatePacketBatchWriterWithCount(conn)
			buffers, dests := packetInputs("one", "two")
			done := make(chan error, 1)
			go func() { _, err := writer.WritePacketBatchCount(buffers, dests); done <- err }()
			select {
			case <-wire.started:
			case <-time.After(3 * time.Second):
				t.Fatal("write not started")
			}
			conn.Close()
			select {
			case err := <-done:
				if !errors.Is(err, net.ErrClosed) {
					t.Fatal(err)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("Close waited behind packet gate")
			}
			assertReleased(t, buffers)
		})
	}
}

type chunkPacketWire struct {
	net.Conn
	failSecond bool
	sizes      []int
}

func (c *chunkPacketWire) WriteVectorisedCount(records []*buf.Buffer) (int64, error) {
	defer buf.ReleaseMulti(records)
	c.sizes = append(c.sizes, len(records))
	limit := len(records)
	fail := c.failSecond && len(c.sizes) == 2
	if fail {
		limit = 2
	}
	var wire []byte
	for _, record := range records[:limit] {
		wire = append(wire, record.Bytes()...)
	}
	if fail {
		wire = append(wire, records[limit].Bytes()[0])
	}
	n, err := c.Conn.Write(wire)
	if err == nil && fail {
		err = io.ErrClosedPipe
	}
	return int64(n), err
}

func TestPacketBatchCountAcrossChunks(t *testing.T) {
	for _, tc := range []packetCase{packetCases[0], packetCases[3], packetCases[4], packetCases[5]} {
		for _, fail := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/fail=%v", tc.name, fail), func(t *testing.T) {
				var wire *chunkPacketWire
				conn, handler := startPacketPair(t, tc, false, func(c net.Conn) net.Conn {
					wire = &chunkPacketWire{Conn: c, failSecond: fail}
					return wire
				})
				payloads := make([]string, 70)
				for i := range payloads {
					payloads[i] = fmt.Sprint(i)
				}
				buffers, dests := packetInputs(payloads...)
				writer, _ := bufio.CreatePacketBatchWriterWithCount(conn)
				n, err := writer.WritePacketBatchCount(buffers, dests)
				want := 70
				if fail {
					want = 66
				}
				if n != want || (!fail && err != nil) || (fail && !errors.Is(err, io.ErrClosedPipe)) {
					t.Fatalf("prefix=%d err=%v", n, err)
				}
				if len(wire.sizes) != 2 || wire.sizes[0] != 64 || wire.sizes[1] != 6 {
					t.Fatalf("unbounded record batches: %v", wire.sizes)
				}
				assertReleased(t, buffers)
				for _, wantPayload := range payloads[:want] {
					select {
					case got := <-handler.seen:
						if got != wantPayload {
							t.Fatalf("payload=%q want=%q", got, wantPayload)
						}
					case <-time.After(3 * time.Second):
						t.Fatal("complete prefix did not reach peer")
					}
				}
			})
		}
	}
}
