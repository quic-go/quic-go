package self_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	mrand "math/rand/v2"
	"net"
	"runtime"
	"sync/atomic"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	quicproxy "github.com/quic-go/quic-go/integrationtests/tools/proxy"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/logging"

	"github.com/stretchr/testify/require"
)

func requireIdleTimeoutError(t *testing.T, err error) {
	t.Helper()
	require.Error(t, err)
	var idleTimeoutErr *quic.IdleTimeoutError
	require.ErrorAs(t, err, &idleTimeoutErr)
	require.True(t, idleTimeoutErr.Timeout())
	var nerr net.Error
	require.True(t, errors.As(err, &nerr))
	require.True(t, nerr.Timeout())
}

func TestHandshakeIdleTimeout(t *testing.T) {
	errChan := make(chan error, 1)
	go func() {
		conn := newUDPConnLocalhost(t)
		_, err := quic.Dial(
			context.Background(),
			newUDPConnLocalhost(t),
			conn.LocalAddr(),
			getTLSClientConfig(),
			getQuicConfig(&quic.Config{HandshakeIdleTimeout: scaleDuration(50 * time.Millisecond)}),
		)
		errChan <- err
	}()
	select {
	case err := <-errChan:
		requireIdleTimeoutError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for dial error")
	}
}

func TestHandshakeTimeoutContext(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	errChan := make(chan error)
	go func() {
		conn := newUDPConnLocalhost(t)
		_, err := quic.Dial(
			ctx,
			newUDPConnLocalhost(t),
			conn.LocalAddr(),
			getTLSClientConfig(),
			getQuicConfig(nil),
		)
		errChan <- err
	}()
	select {
	case err := <-errChan:
		require.ErrorIs(t, err, context.DeadlineExceeded)
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for dial error")
	}
}

func TestHandshakeTimeout0RTTContext(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	errChan := make(chan error)
	go func() {
		conn := newUDPConnLocalhost(t)
		_, err := quic.DialEarly(
			ctx,
			newUDPConnLocalhost(t),
			conn.LocalAddr(),
			getTLSClientConfig(),
			getQuicConfig(nil),
		)
		errChan <- err
	}()
	select {
	case err := <-errChan:
		require.ErrorIs(t, err, context.DeadlineExceeded)
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for dial error")
	}
}

func TestIdleTimeout(t *testing.T) {
	idleTimeout := scaleDuration(200 * time.Millisecond)

	server, err := quic.Listen(
		newUDPConnLocalhost(t),
		getTLSConfig(),
		getQuicConfig(&quic.Config{DisablePathMTUDiscovery: true}),
	)
	require.NoError(t, err)
	defer server.Close()

	var drop atomic.Bool
	proxy := quicproxy.Proxy{
		Conn:       newUDPConnLocalhost(t),
		ServerAddr: server.Addr().(*net.UDPAddr),
		DropPacket: func(quicproxy.Direction, net.Addr, net.Addr, []byte) bool { return drop.Load() },
	}
	require.NoError(t, proxy.Start())
	defer proxy.Close()

	conn, err := quic.Dial(
		context.Background(),
		newUDPConnLocalhost(t),
		proxy.LocalAddr(),
		getTLSClientConfig(),
		getQuicConfig(&quic.Config{DisablePathMTUDiscovery: true, MaxIdleTimeout: idleTimeout}),
	)
	require.NoError(t, err)

	serverConn, err := server.Accept(context.Background())
	require.NoError(t, err)
	str, err := serverConn.OpenStream()
	require.NoError(t, err)
	_, err = str.Write([]byte("foobar"))
	require.NoError(t, err)

	strIn, err := conn.AcceptStream(context.Background())
	require.NoError(t, err)
	strOut, err := conn.OpenStream()
	require.NoError(t, err)
	_, err = strIn.Read(make([]byte, 6))
	require.NoError(t, err)

	drop.Store(true)
	time.Sleep(2 * idleTimeout)
	_, err = strIn.Write([]byte("test"))
	requireIdleTimeoutError(t, err)
	_, err = strIn.Read([]byte{0})
	requireIdleTimeoutError(t, err)
	_, err = strOut.Write([]byte("test"))
	requireIdleTimeoutError(t, err)
	_, err = strOut.Read([]byte{0})
	requireIdleTimeoutError(t, err)
	_, err = conn.OpenStream()
	requireIdleTimeoutError(t, err)
	_, err = conn.OpenUniStream()
	requireIdleTimeoutError(t, err)
	_, err = conn.AcceptStream(context.Background())
	requireIdleTimeoutError(t, err)
	_, err = conn.AcceptUniStream(context.Background())
	requireIdleTimeoutError(t, err)
}

func TestKeepAlive(t *testing.T) {
	idleTimeout := scaleDuration(150 * time.Millisecond)
	if runtime.GOOS == "windows" {
		// increase the duration, since timers on Windows are not very precise
		idleTimeout = max(idleTimeout, 600*time.Millisecond)
	}

	server, err := quic.Listen(
		newUDPConnLocalhost(t),
		getTLSConfig(),
		getQuicConfig(&quic.Config{DisablePathMTUDiscovery: true}),
	)
	require.NoError(t, err)
	defer server.Close()

	var drop atomic.Bool
	proxy := quicproxy.Proxy{
		Conn:       newUDPConnLocalhost(t),
		ServerAddr: server.Addr().(*net.UDPAddr),
		DropPacket: func(quicproxy.Direction, net.Addr, net.Addr, []byte) bool { return drop.Load() },
	}
	require.NoError(t, proxy.Start())
	defer proxy.Close()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	conn, err := quic.Dial(
		ctx,
		newUDPConnLocalhost(t),
		proxy.LocalAddr(),
		getTLSClientConfig(),
		getQuicConfig(&quic.Config{
			MaxIdleTimeout:          idleTimeout,
			KeepAlivePeriod:         idleTimeout / 2,
			DisablePathMTUDiscovery: true,
		}),
	)
	require.NoError(t, err)

	serverConn, err := server.Accept(ctx)
	require.NoError(t, err)

	// wait longer than the idle timeout
	time.Sleep(3 * idleTimeout)
	str, err := conn.OpenUniStream()
	require.NoError(t, err)
	_, err = str.Write([]byte("foobar"))
	require.NoError(t, err)

	// verify connection is still alive
	select {
	case <-serverConn.Context().Done():
		t.Fatal("server connection closed unexpectedly")
	default:
	}

	// idle timeout will still kick in if PINGs are dropped
	drop.Store(true)
	time.Sleep(2 * idleTimeout)
	_, err = str.Write([]byte("foobar"))
	var nerr net.Error
	require.True(t, errors.As(err, &nerr))
	require.True(t, nerr.Timeout())

	// can't rely on the server connection closing, since we impose a minimum idle timeout of 5s,
	// see https://github.com/quic-go/quic-go/issues/4751
	serverConn.CloseWithError(0, "")
}

func TestTimeoutAfterInactivity(t *testing.T) {
	idleTimeout := scaleDuration(150 * time.Millisecond)
	if runtime.GOOS == "windows" {
		// increase the duration, since timers on Windows are not very precise
		idleTimeout = max(idleTimeout, 600*time.Millisecond)
	}

	server, err := quic.Listen(
		newUDPConnLocalhost(t),
		getTLSConfig(),
		getQuicConfig(&quic.Config{DisablePathMTUDiscovery: true}),
	)
	require.NoError(t, err)
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	counter, tr := newPacketTracer()
	conn, err := quic.Dial(
		ctx,
		newUDPConnLocalhost(t),
		server.Addr(),
		getTLSClientConfig(),
		getQuicConfig(&quic.Config{
			MaxIdleTimeout:          idleTimeout,
			Tracer:                  newTracer(tr),
			DisablePathMTUDiscovery: true,
		}),
	)
	require.NoError(t, err)

	serverConn, err := server.Accept(ctx)
	require.NoError(t, err)

	ctx, cancel = context.WithTimeout(context.Background(), 2*idleTimeout)
	defer cancel()
	_, err = conn.AcceptStream(ctx)
	requireIdleTimeoutError(t, err)

	var lastAckElicitingPacketSentAt time.Time
	for _, p := range counter.getSentShortHeaderPackets() {
		var hasAckElicitingFrame bool
		for _, f := range p.frames {
			if _, ok := f.(*logging.AckFrame); ok {
				continue
			}
			hasAckElicitingFrame = true
			break
		}
		if hasAckElicitingFrame {
			lastAckElicitingPacketSentAt = p.time
		}
	}
	rcvdPackets := counter.getRcvdShortHeaderPackets()
	lastPacketRcvdAt := rcvdPackets[len(rcvdPackets)-1].time
	// We're ignoring here that only the first ack-eliciting packet sent resets the idle timeout.
	// This is ok since we're dealing with a lossless connection here,
	// and we'd expect to receive an ACK for additional other ack-eliciting packet sent.
	timeSinceLastAckEliciting := time.Since(lastAckElicitingPacketSentAt)
	timeSinceLastRcvd := time.Since(lastPacketRcvdAt)
	maxDuration := max(timeSinceLastAckEliciting, timeSinceLastRcvd)
	require.GreaterOrEqual(t, maxDuration, idleTimeout)
	require.Less(t, maxDuration, idleTimeout*6/5)

	select {
	case <-serverConn.Context().Done():
		t.Fatal("server connection closed unexpectedly")
	default:
	}

	serverConn.CloseWithError(0, "")
}

func TestTimeoutAfterSendingPacket(t *testing.T) {
	idleTimeout := scaleDuration(150 * time.Millisecond)
	if runtime.GOOS == "windows" {
		// increase the duration, since timers on Windows are not very precise
		idleTimeout = max(idleTimeout, 600*time.Millisecond)
	}

	server, err := quic.Listen(
		newUDPConnLocalhost(t),
		getTLSConfig(),
		getQuicConfig(&quic.Config{DisablePathMTUDiscovery: true}),
	)
	require.NoError(t, err)
	defer server.Close()

	var drop atomic.Bool
	proxy := quicproxy.Proxy{
		Conn:       newUDPConnLocalhost(t),
		ServerAddr: server.Addr().(*net.UDPAddr),
		DropPacket: func(quicproxy.Direction, net.Addr, net.Addr, []byte) bool { return drop.Load() },
	}
	require.NoError(t, proxy.Start())
	defer proxy.Close()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	conn, err := quic.Dial(
		ctx,
		newUDPConnLocalhost(t),
		proxy.LocalAddr(),
		getTLSClientConfig(),
		getQuicConfig(&quic.Config{MaxIdleTimeout: idleTimeout, DisablePathMTUDiscovery: true}),
	)
	require.NoError(t, err)

	serverConn, err := server.Accept(ctx)
	require.NoError(t, err)

	// wait half the idle timeout, then send a packet
	time.Sleep(idleTimeout / 2)
	drop.Store(true)
	str, err := conn.OpenUniStream()
	require.NoError(t, err)
	_, err = str.Write([]byte("foobar"))
	require.NoError(t, err)

	// now make sure that the idle timeout is based on this packet
	startTime := time.Now()
	ctx, cancel = context.WithTimeout(context.Background(), 2*idleTimeout)
	defer cancel()
	_, err = conn.AcceptStream(ctx)
	requireIdleTimeoutError(t, err)
	dur := time.Since(startTime)
	require.GreaterOrEqual(t, dur, idleTimeout)
	require.Less(t, dur, idleTimeout*12/10)

	// Verify server connection is still open
	select {
	case <-serverConn.Context().Done():
		t.Fatal("server connection closed unexpectedly")
	default:
	}
	serverConn.CloseWithError(0, "")
}

type faultyConn struct {
	net.PacketConn

	MaxPackets int
	counter    atomic.Int32
}

func (c *faultyConn) ReadFrom(p []byte) (int, net.Addr, error) {
	n, addr, err := c.PacketConn.ReadFrom(p)
	counter := c.counter.Add(1)
	if counter <= int32(c.MaxPackets) {
		return n, addr, err
	}
	return 0, nil, io.ErrClosedPipe
}

func (c *faultyConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	counter := c.counter.Add(1)
	if counter <= int32(c.MaxPackets) {
		return c.PacketConn.WriteTo(p, addr)
	}
	return 0, io.ErrClosedPipe
}

func TestFaultyPacketConn(t *testing.T) {
	t.Run("client", func(t *testing.T) {
		testFaultyPacketConn(t, protocol.PerspectiveClient)
	})

	t.Run("server", func(t *testing.T) {
		testFaultyPacketConn(t, protocol.PerspectiveServer)
	})
}

func testFaultyPacketConn(t *testing.T, pers protocol.Perspective) {
	handshakeTimeout := scaleDuration(100 * time.Millisecond)

	runServer := func(ln *quic.Listener) error {
		conn, err := ln.Accept(context.Background())
		if err != nil {
			return err
		}
		str, err := conn.OpenUniStream()
		if err != nil {
			return err
		}
		defer str.Close()
		_, err = str.Write(PRData)
		return err
	}

	runClient := func(conn quic.Connection) error {
		str, err := conn.AcceptUniStream(context.Background())
		if err != nil {
			return err
		}
		data, err := io.ReadAll(str)
		if err != nil {
			return err
		}
		if !bytes.Equal(data, PRData) {
			return fmt.Errorf("wrong data: %q vs %q", data, PRData)
		}
		return conn.CloseWithError(0, "done")
	}

	var cconn net.PacketConn = newUDPConnLocalhost(t)
	var sconn net.PacketConn = newUDPConnLocalhost(t)
	maxPackets := mrand.IntN(25)
	t.Logf("blocking %s's connection after %d packets", pers, maxPackets)
	switch pers {
	case protocol.PerspectiveClient:
		cconn = &faultyConn{PacketConn: cconn, MaxPackets: maxPackets}
	case protocol.PerspectiveServer:
		sconn = &faultyConn{PacketConn: sconn, MaxPackets: maxPackets}
	}

	ln, err := quic.Listen(
		sconn,
		getTLSConfig(),
		getQuicConfig(&quic.Config{
			HandshakeIdleTimeout:    handshakeTimeout,
			MaxIdleTimeout:          handshakeTimeout,
			KeepAlivePeriod:         handshakeTimeout / 2,
			DisablePathMTUDiscovery: true,
		}),
	)
	require.NoError(t, err)
	defer ln.Close()

	serverErrChan := make(chan error, 1)
	go func() { serverErrChan <- runServer(ln) }()

	clientErrChan := make(chan error, 1)
	go func() {
		conn, err := quic.Dial(
			context.Background(),
			cconn,
			ln.Addr(),
			getTLSClientConfig(),
			getQuicConfig(&quic.Config{
				HandshakeIdleTimeout:    handshakeTimeout,
				MaxIdleTimeout:          handshakeTimeout,
				KeepAlivePeriod:         handshakeTimeout / 2,
				DisablePathMTUDiscovery: true,
			}),
		)
		if err != nil {
			clientErrChan <- err
			return
		}
		clientErrChan <- runClient(conn)
	}()

	var clientErr error
	select {
	case clientErr = <-clientErrChan:
	case <-time.After(5 * handshakeTimeout):
		t.Fatal("timeout waiting for client error")
	}
	require.Error(t, clientErr)
	if pers == protocol.PerspectiveClient {
		require.Contains(t, clientErr.Error(), io.ErrClosedPipe.Error())
	} else {
		var nerr net.Error
		require.True(t, errors.As(clientErr, &nerr))
		require.True(t, nerr.Timeout())
	}

	require.Eventually(t, func() bool { return !areHandshakesRunning() }, 5*handshakeTimeout, 5*time.Millisecond)

	select {
	case serverErr := <-serverErrChan: // The handshake completed on the server side.
		require.Error(t, serverErr)
		if pers == protocol.PerspectiveServer {
			require.Contains(t, serverErr.Error(), io.ErrClosedPipe.Error())
		} else {
			var nerr net.Error
			require.True(t, errors.As(serverErr, &nerr))
			require.True(t, nerr.Timeout())
		}
	default: // The handshake didn't complete
		require.NoError(t, ln.Close())
		select {
		case <-serverErrChan:
		case <-time.After(time.Second):
			t.Fatal("timeout waiting for server to close")
		}
	}
}
