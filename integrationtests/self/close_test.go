package self_test

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	quicproxy "github.com/quic-go/quic-go/integrationtests/tools/proxy"
	"github.com/quic-go/quic-go/internal/protocol"

	"github.com/stretchr/testify/require"
)

func TestConnectionCloseRetransmission(t *testing.T) {
	server, err := quic.Listen(
		newUDPConnLocalhost(t),
		getTLSConfig(),
		getQuicConfig(&quic.Config{DisablePathMTUDiscovery: true}),
	)
	require.NoError(t, err)
	defer server.Close()

	var drop atomic.Bool
	dropped := make(chan []byte, 100)
	proxy := &quicproxy.Proxy{
		Conn:       newUDPConnLocalhost(t),
		ServerAddr: server.Addr().(*net.UDPAddr),
		DelayPacket: func(quicproxy.Direction, net.Addr, net.Addr, []byte) time.Duration {
			return 5 * time.Millisecond // 10ms RTT
		},
		DropPacket: func(dir quicproxy.Direction, _, _ net.Addr, b []byte) bool {
			if drop := drop.Load(); drop && dir == quicproxy.DirectionOutgoing {
				dropped <- b
				return true
			}
			return false
		},
	}
	require.NoError(t, proxy.Start())
	defer proxy.Close()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	conn, err := quic.Dial(ctx, newUDPConnLocalhost(t), proxy.LocalAddr(), getTLSClientConfig(), getQuicConfig(nil))
	require.NoError(t, err)
	defer conn.CloseWithError(0, "")

	sconn, err := server.Accept(ctx)
	require.NoError(t, err)
	time.Sleep(100 * time.Millisecond)
	drop.Store(true)
	sconn.CloseWithError(1337, "closing")

	// send 100 packets
	for i := 0; i < 100; i++ {
		str, err := conn.OpenStream()
		require.NoError(t, err)
		_, err = str.Write([]byte("foobar"))
		require.NoError(t, err)
		time.Sleep(time.Millisecond)
	}

	// Expect retransmissions of the CONNECTION_CLOSE for the
	// 1st, 2nd, 4th, 8th, 16th, 32th, 64th packet: 7 in total (+1 for the original packet)
	var packets [][]byte
	for i := 0; i < 8; i++ {
		select {
		case p := <-dropped:
			packets = append(packets, p)
		case <-time.After(time.Second):
			t.Fatal("timeout waiting for CONNECTION_CLOSE retransmission")
		}
	}

	// verify all retransmitted packets were identical
	for i := 1; i < len(packets); i++ {
		require.Equal(t, packets[0], packets[i])
	}
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
	conns := make([]quic.Connection, 0, protocol.MaxAcceptQueueSize)
	for i := 0; i < protocol.MaxAcceptQueueSize; i++ {
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
		require.NoError(t, conns[i].Context().Err(), "client connection closed")
		require.NoError(t, c.Context().Err(), "server connection closed")
		conns[i].CloseWithError(0, "")
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
		c.PacketConn.SetDeadline(time.Now())
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
		testErr := errors.New("test error")
		testTransportClose(t, bc, func() { bc.Break(testErr) }, testErr)
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
