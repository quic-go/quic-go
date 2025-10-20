package self_test

import (
	"context"
	"crypto/tls"
	"math"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/synctest"
	"github.com/quic-go/quic-go/testutils/simnet"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type droppingRouter struct {
	simnet.PerfectRouter

	Drop func(simnet.Packet) bool
}

func (d *droppingRouter) SendPacket(p simnet.Packet) error {
	if d.Drop(p) {
		return nil
	}
	return d.PerfectRouter.SendPacket(p)
}

var _ simnet.Router = &droppingRouter{}

func TestConnectionCloseRetransmission(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const rtt = 10 * time.Millisecond
		serverAddr := &net.UDPAddr{IP: net.ParseIP("1.0.0.2"), Port: 9002}

		var drop atomic.Bool
		var mx sync.Mutex
		var dropped [][]byte
		n := &simnet.Simnet{
			Router: &droppingRouter{Drop: func(p simnet.Packet) bool {
				shouldDrop := drop.Load() && p.From.String() == serverAddr.String()
				if shouldDrop {
					mx.Lock()
					dropped = append(dropped, p.Data)
					mx.Unlock()
				}
				return shouldDrop
			}},
		}
		settings := simnet.NodeBiDiLinkSettings{
			Downlink: simnet.LinkSettings{BitsPerSecond: math.MaxInt, Latency: rtt / 4},
			Uplink:   simnet.LinkSettings{BitsPerSecond: math.MaxInt, Latency: rtt / 4},
		}
		clientConn := n.NewEndpoint(&net.UDPAddr{IP: net.ParseIP("1.0.0.1"), Port: 9001}, settings)
		serverConn := n.NewEndpoint(serverAddr, settings)
		require.NoError(t, n.Start())
		defer n.Close()

		tr := &quic.Transport{Conn: serverConn}
		defer tr.Close()
		server, err := tr.Listen(
			getTLSConfig(),
			getQuicConfig(&quic.Config{DisablePathMTUDiscovery: true}),
		)
		require.NoError(t, err)
		defer server.Close()

		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		conn, err := quic.Dial(ctx, clientConn, server.Addr(), getTLSClientConfig(), getQuicConfig(nil))
		require.NoError(t, err)
		defer conn.CloseWithError(0, "")

		sconn, err := server.Accept(ctx)
		require.NoError(t, err)

		time.Sleep(rtt)

		drop.Store(true)
		sconn.CloseWithError(1337, "closing")

		// send 100 packets
		for range 100 {
			str, err := conn.OpenStream()
			require.NoError(t, err)
			_, err = str.Write([]byte("foobar"))
			require.NoError(t, err)

			// A closed connection will drop packets if a very short queue overflows.
			// Waiting for one nanosecond makes synctest process the packet before advancing
			// the synthetic clock.
			time.Sleep(time.Nanosecond)
		}

		time.Sleep(rtt)

		mx.Lock()
		defer mx.Unlock()

		// Expect retransmissions of the CONNECTION_CLOSE for the
		// 1st, 2nd, 4th, 8th, 16th, 32th, 64th packet: 7 in total (+1 for the original packet)
		require.Len(t, dropped, 8)

		// verify all retransmitted packets were identical
		for i := 1; i < len(dropped); i++ {
			require.Equal(t, dropped[0], dropped[i])
		}
	})
}

func TestDrainServerAcceptQueue(t *testing.T) {
	server, err := quic.Listen(newUDPConnLocalhost(t), getTLSConfig(), getQuicConfig(nil))
	require.NoError(t, err)
	defer server.Close()

	dialer := &quic.Transport{Conn: newUDPConnLocalhost(t)}
	defer dialer.Close()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	// fill up the accept queue
	conns := make([]*quic.Conn, 0, protocol.MaxAcceptQueueSize)
	for range protocol.MaxAcceptQueueSize {
		conn, err := dialer.Dial(ctx, server.Addr(), getTLSClientConfig(), getQuicConfig(nil))
		require.NoError(t, err)
		conns = append(conns, conn)
	}
	time.Sleep(scaleDuration(25 * time.Millisecond)) // wait for connections to be queued

	server.Close()
	for i := range protocol.MaxAcceptQueueSize {
		c, err := server.Accept(ctx)
		require.NoError(t, err)
		// make sure the connection is not closed
		require.NoError(t, context.Cause(conns[i].Context()), "client connection closed")
		require.NoError(t, context.Cause(c.Context()), "server connection closed")
		c.CloseWithError(0, "")
	}
	_, err = server.Accept(ctx)
	require.ErrorIs(t, err, quic.ErrServerClosed)
}

type brokenConn struct {
	net.PacketConn

	broken   chan struct{}
	breakErr atomic.Pointer[error]
}

func newBrokenConn(conn net.PacketConn) *brokenConn {
	c := &brokenConn{
		PacketConn: conn,
		broken:     make(chan struct{}),
	}
	go func() {
		<-c.broken
		// make calls to ReadFrom return
		c.SetDeadline(time.Now())
	}()
	return c
}

func (c *brokenConn) ReadFrom(b []byte) (int, net.Addr, error) {
	if err := c.breakErr.Load(); err != nil {
		return 0, nil, *err
	}
	n, addr, err := c.PacketConn.ReadFrom(b)
	if err != nil {
		select {
		case <-c.broken:
			err = *c.breakErr.Load()
		default:
		}
	}
	return n, addr, err
}

func (c *brokenConn) Break(e error) {
	c.breakErr.Store(&e)
	close(c.broken)
}

func TestTransportClose(t *testing.T) {
	t.Run("Close", func(t *testing.T) {
		conn := newUDPConnLocalhost(t)
		testTransportClose(t, conn, func() { conn.Close() }, nil)
	})

	t.Run("connection error", func(t *testing.T) {
		t.Setenv("QUIC_GO_DISABLE_RECEIVE_BUFFER_WARNING", "true")

		bc := newBrokenConn(newUDPConnLocalhost(t))
		testTransportClose(t, bc, func() { bc.Break(assert.AnError) }, assert.AnError)
	})
}

func testTransportClose(t *testing.T, conn net.PacketConn, closeFn func(), expectedErr error) {
	server := newUDPConnLocalhost(t)
	tr := &quic.Transport{Conn: conn}

	errChan := make(chan error, 1)
	go func() {
		_, err := tr.Dial(context.Background(), server.LocalAddr(), &tls.Config{}, getQuicConfig(nil))
		errChan <- err
	}()

	select {
	case <-errChan:
		t.Fatal("didn't expect Dial to return yet")
	case <-time.After(scaleDuration(10 * time.Millisecond)):
	}

	closeFn()

	select {
	case err := <-errChan:
		require.Error(t, err)
		require.ErrorIs(t, err, quic.ErrTransportClosed)
		if expectedErr != nil {
			require.ErrorIs(t, err, expectedErr)
		}
	case <-time.After(time.Second):
		t.Fatal("timeout")
	}

	// it's not possible to dial new connections
	ctx, cancel := context.WithTimeout(context.Background(), scaleDuration(50*time.Millisecond))
	defer cancel()
	_, err := tr.Dial(ctx, server.LocalAddr(), &tls.Config{}, getQuicConfig(nil))
	require.Error(t, err)
	require.ErrorIs(t, err, quic.ErrTransportClosed)
	if expectedErr != nil {
		require.ErrorIs(t, err, expectedErr)
	}

	// it's not possible to create new listeners
	_, err = tr.Listen(&tls.Config{}, nil)
	require.Error(t, err)
	require.ErrorIs(t, err, quic.ErrTransportClosed)
	if expectedErr != nil {
		require.ErrorIs(t, err, expectedErr)
	}
}
