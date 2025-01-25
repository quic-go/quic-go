package self_test

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	quicproxy "github.com/quic-go/quic-go/integrationtests/tools/proxy"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/wire"
	"github.com/quic-go/quic-go/logging"

	"github.com/stretchr/testify/require"
)

func runCountingProxyAndCount0RTTPackets(t *testing.T, serverPort int, rtt time.Duration) (*quicproxy.Proxy, *atomic.Uint32) {
	t.Helper()
	var num0RTTPackets atomic.Uint32
	proxy := &quicproxy.Proxy{
		Conn:       newUPDConnLocalhost(t),
		ServerAddr: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: serverPort},
		DelayPacket: func(_ quicproxy.Direction, data []byte) time.Duration {
			if contains0RTTPacket(data) {
				num0RTTPackets.Add(1)
			}
			return rtt / 2
		},
	}
	require.NoError(t, proxy.Start())
	t.Cleanup(func() { proxy.Close() })
	return proxy, &num0RTTPackets
}

func dialAndReceiveTicket(
	t *testing.T,
	rtt time.Duration,
	serverTLSConf *tls.Config,
	serverConf *quic.Config,
	clientSessionCache tls.ClientSessionCache,
) (clientTLSConf *tls.Config) {
	t.Helper()

	ln, err := quic.ListenEarly(newUPDConnLocalhost(t), serverTLSConf, serverConf)
	require.NoError(t, err)
	defer ln.Close()

	proxy := &quicproxy.Proxy{
		Conn:        newUPDConnLocalhost(t),
		ServerAddr:  ln.Addr().(*net.UDPAddr),
		DelayPacket: func(_ quicproxy.Direction, _ []byte) time.Duration { return rtt / 2 },
	}
	require.NoError(t, proxy.Start())
	defer proxy.Close()

	clientTLSConf = getTLSClientConfig()
	puts := make(chan string, 100)
	cache := clientSessionCache
	if cache == nil {
		cache = tls.NewLRUClientSessionCache(100)
	}
	clientTLSConf.ClientSessionCache = newClientSessionCache(cache, nil, puts)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	conn, err := quic.Dial(ctx, newUPDConnLocalhost(t), proxy.LocalAddr(), clientTLSConf, getQuicConfig(nil))
	require.NoError(t, err)
	require.False(t, conn.ConnectionState().Used0RTT)

	select {
	case <-puts:
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for session ticket")
	}
	require.NoError(t, conn.CloseWithError(0, ""))

	serverConn, err := ln.Accept(ctx)
	require.NoError(t, err)

	select {
	case <-serverConn.Context().Done():
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for connection to close")
	}
	return clientTLSConf
}

func transfer0RTTData(
	t *testing.T,
	ln *quic.EarlyListener,
	proxyAddr net.Addr,
	clientTLSConf *tls.Config,
	clientConf *quic.Config,
	testdata []byte, // data to transfer
) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	conn, err := quic.DialEarly(ctx, newUPDConnLocalhost(t), proxyAddr, clientTLSConf, clientConf)
	require.NoError(t, err)

	errChan := make(chan error, 1)
	serverConnChan := make(chan quic.EarlyConnection, 1)
	go func() {
		defer close(errChan)
		conn, err := ln.Accept(ctx)
		if err != nil {
			errChan <- err
			return
		}
		serverConnChan <- conn
		str, err := conn.AcceptStream(ctx)
		if err != nil {
			errChan <- err
			return
		}
		defer str.Close()
		if _, err := io.Copy(str, str); err != nil {
			errChan <- err
			return
		}
	}()

	str, err := conn.OpenStream()
	require.NoError(t, err)
	_, err = str.Write(testdata)
	require.NoError(t, err)
	require.NoError(t, str.Close())
	select {
	case <-conn.HandshakeComplete():
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for handshake to complete")
	}
	// wait for the EOF from the server to arrive before closing the conn
	_, err = io.ReadAll(&readerWithTimeout{Reader: str, Timeout: 10 * time.Second})
	require.NoError(t, err)

	select {
	case err := <-errChan:
		require.NoError(t, err)
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for server to process data")
	}

	var serverConn quic.EarlyConnection
	select {
	case serverConn = <-serverConnChan:
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for server to process data")
	}

	require.True(t, conn.ConnectionState().Used0RTT)
	require.True(t, serverConn.ConnectionState().Used0RTT)
	conn.CloseWithError(0, "")

	select {
	case <-serverConn.Context().Done():
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for connection to close")
	}
}

func Test0RTTTransfer(t *testing.T) {
	const rtt = 5 * time.Millisecond
	tlsConf := getTLSConfig()
	clientTLSConf := dialAndReceiveTicket(t, rtt, tlsConf, getQuicConfig(&quic.Config{Allow0RTT: true}), nil)

	counter, tracer := newPacketTracer()
	ln, err := quic.ListenEarly(
		newUPDConnLocalhost(t),
		tlsConf,
		getQuicConfig(&quic.Config{Allow0RTT: true, Tracer: newTracer(tracer)}),
	)
	require.NoError(t, err)
	defer ln.Close()

	proxy, num0RTTPackets := runCountingProxyAndCount0RTTPackets(t, ln.Addr().(*net.UDPAddr).Port, rtt)
	require.Zero(t, num0RTTPackets.Load())

	transfer0RTTData(t, ln, proxy.LocalAddr(), clientTLSConf, getQuicConfig(nil), PRData)

	num0RTT := num0RTTPackets.Load()
	t.Logf("sent %d 0-RTT packets", num0RTT)
	zeroRTTPackets := counter.getRcvd0RTTPacketNumbers()
	t.Logf("received %d 0-RTT packets", len(zeroRTTPackets))
	require.Greater(t, len(zeroRTTPackets), 10)
	require.Contains(t, zeroRTTPackets, protocol.PacketNumber(0))
}

func Test0RTTDisabledOnDial(t *testing.T) {
	const rtt = 5 * time.Millisecond
	tlsConf := getTLSConfig()
	clientTLSConf := dialAndReceiveTicket(t, rtt, tlsConf, getQuicConfig(&quic.Config{Allow0RTT: true}), nil)

	counter, tracer := newPacketTracer()
	ln, err := quic.ListenEarly(
		newUPDConnLocalhost(t),
		tlsConf,
		getQuicConfig(&quic.Config{Allow0RTT: true, Tracer: newTracer(tracer)}),
	)
	require.NoError(t, err)
	defer ln.Close()

	proxy, num0RTTPackets := runCountingProxyAndCount0RTTPackets(t, ln.Addr().(*net.UDPAddr).Port, rtt)
	require.Zero(t, num0RTTPackets.Load())

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	conn, err := quic.Dial(ctx, newUPDConnLocalhost(t), proxy.LocalAddr(), clientTLSConf, getQuicConfig(nil))
	require.NoError(t, err)
	// session Resumption is enabled at the TLS layer, but not 0-RTT at the QUIC layer
	require.True(t, conn.ConnectionState().TLS.DidResume)
	require.False(t, conn.ConnectionState().Used0RTT)
	conn.CloseWithError(0, "")

	require.Zero(t, num0RTTPackets.Load())
	require.Empty(t, counter.getRcvd0RTTPacketNumbers())
}

func Test0RTTWaitForHandshakeCompletion(t *testing.T) {
	const rtt = 5 * time.Millisecond
	tlsConf := getTLSConfig()
	clientTLSConf := dialAndReceiveTicket(t, rtt, tlsConf, getQuicConfig(&quic.Config{Allow0RTT: true}), nil)

	zeroRTTData := GeneratePRData(5 << 10)
	oneRTTData := PRData

	counter, tracer := newPacketTracer()
	ln, err := quic.ListenEarly(
		newUPDConnLocalhost(t),
		tlsConf,
		getQuicConfig(&quic.Config{
			Allow0RTT: true,
			Tracer:    newTracer(tracer),
		}),
	)
	require.NoError(t, err)
	defer ln.Close()

	proxy, _ := runCountingProxyAndCount0RTTPackets(t, ln.Addr().(*net.UDPAddr).Port, rtt)

	// now accept the second connection, and receive the 0-RTT data
	errChan := make(chan error, 1)
	firstStrDataChan := make(chan []byte, 1)
	secondStrDataChan := make(chan []byte, 1)
	go func() {
		defer close(errChan)
		conn, err := ln.Accept(context.Background())
		if err != nil {
			errChan <- err
			return
		}
		str, err := conn.AcceptUniStream(context.Background())
		if err != nil {
			errChan <- err
			return
		}
		data, err := io.ReadAll(str)
		if err != nil {
			errChan <- err
			return
		}
		firstStrDataChan <- data
		str, err = conn.AcceptUniStream(context.Background())
		if err != nil {
			errChan <- err
			return
		}
		data, err = io.ReadAll(str)
		if err != nil {
			errChan <- err
			return
		}
		secondStrDataChan <- data
		<-conn.Context().Done()
	}()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	conn, err := quic.DialEarly(
		ctx,
		newUPDConnLocalhost(t),
		proxy.LocalAddr(),
		clientTLSConf,
		getQuicConfig(nil),
	)
	require.NoError(t, err)
	firstStr, err := conn.OpenUniStream()
	require.NoError(t, err)
	_, err = firstStr.Write(zeroRTTData)
	require.NoError(t, err)
	require.NoError(t, firstStr.Close())

	// wait for the handshake to complete
	select {
	case <-conn.HandshakeComplete():
	case <-time.After(time.Second):
		t.Fatal("handshake did not complete in time")
	}
	str, err := conn.OpenUniStream()
	require.NoError(t, err)
	_, err = str.Write(PRData)
	require.NoError(t, err)
	require.NoError(t, str.Close())

	select {
	case data := <-firstStrDataChan:
		require.Equal(t, zeroRTTData, data)
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for first stream data")
	}
	select {
	case data := <-secondStrDataChan:
		require.Equal(t, oneRTTData, data)
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for second stream data")
	}
	conn.CloseWithError(0, "")
	select {
	case err := <-errChan:
		require.NoError(t, err, "server error")
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for connection to close")
	}

	// check that 0-RTT packets only contain STREAM frames for the first stream
	var num0RTT int
	for _, p := range counter.getRcvdLongHeaderPackets() {
		if p.hdr.Header.Type != protocol.PacketType0RTT {
			continue
		}
		for _, f := range p.frames {
			sf, ok := f.(*logging.StreamFrame)
			if !ok {
				continue
			}
			num0RTT++
			require.Equal(t, firstStr.StreamID(), sf.StreamID)
		}
	}
	t.Logf("received %d STREAM frames in 0-RTT packets", num0RTT)
	require.NotZero(t, num0RTT)
}

func Test0RTTDataLoss(t *testing.T) {
	const rtt = 5 * time.Millisecond
	tlsConf := getTLSConfig()
	clientConf := dialAndReceiveTicket(t, rtt, tlsConf, getQuicConfig(&quic.Config{Allow0RTT: true}), nil)

	counter, tracer := newPacketTracer()
	ln, err := quic.ListenEarly(
		newUPDConnLocalhost(t),
		tlsConf,
		getQuicConfig(&quic.Config{Allow0RTT: true, Tracer: newTracer(tracer)}),
	)
	require.NoError(t, err)
	defer ln.Close()

	var num0RTTPackets, numDropped atomic.Uint32
	proxy := quicproxy.Proxy{
		Conn:        newUPDConnLocalhost(t),
		ServerAddr:  ln.Addr().(*net.UDPAddr),
		DelayPacket: func(_ quicproxy.Direction, data []byte) time.Duration { return rtt / 2 },
		DropPacket: func(_ quicproxy.Direction, data []byte) bool {
			if !wire.IsLongHeaderPacket(data[0]) {
				return false
			}
			hdr, _, _, _ := wire.ParsePacket(data)
			if hdr.Type == protocol.PacketType0RTT {
				count := num0RTTPackets.Add(1)
				// drop 25% of the 0-RTT packets
				drop := count%4 == 0
				if drop {
					numDropped.Add(1)
				}
				return drop
			}
			return false
		},
	}
	require.NoError(t, proxy.Start())
	defer proxy.Close()

	transfer0RTTData(t, ln, proxy.LocalAddr(), clientConf, nil, PRData)

	num0RTT := num0RTTPackets.Load()
	dropped := numDropped.Load()
	t.Logf("sent %d 0-RTT packets, dropped %d of those.", num0RTT, dropped)
	require.NotZero(t, num0RTT)
	require.NotZero(t, dropped)
	require.NotEmpty(t, counter.getRcvd0RTTPacketNumbers())
}

func Test0RTTRetransmitOnRetry(t *testing.T) {
	const rtt = 5 * time.Millisecond
	tlsConf := getTLSConfig()
	clientConf := dialAndReceiveTicket(t, rtt, tlsConf, getQuicConfig(&quic.Config{Allow0RTT: true}), nil)

	countZeroRTTBytes := func(data []byte) (n protocol.ByteCount) {
		for len(data) > 0 {
			hdr, _, rest, err := wire.ParsePacket(data)
			if err != nil {
				return
			}
			data = rest
			if hdr.Type == protocol.PacketType0RTT {
				n += hdr.Length - 16 /* AEAD tag */
			}
		}
		return
	}

	counter, tracer := newPacketTracer()
	tr := &quic.Transport{
		Conn:                newUPDConnLocalhost(t),
		VerifySourceAddress: func(net.Addr) bool { return true },
	}
	addTracer(tr)
	defer tr.Close()
	ln, err := tr.ListenEarly(tlsConf, getQuicConfig(&quic.Config{Allow0RTT: true, Tracer: newTracer(tracer)}))
	require.NoError(t, err)
	defer ln.Close()

	type connIDCounter struct {
		connID protocol.ConnectionID
		bytes  protocol.ByteCount
	}
	var mutex sync.Mutex
	var connIDToCounter []*connIDCounter
	proxy := quicproxy.Proxy{
		Conn:       newUPDConnLocalhost(t),
		ServerAddr: ln.Addr().(*net.UDPAddr),
		DelayPacket: func(dir quicproxy.Direction, data []byte) time.Duration {
			connID, err := wire.ParseConnectionID(data, 0)
			if err != nil {
				panic("failed to parse connection ID")
			}
			if l := countZeroRTTBytes(data); l != 0 {
				mutex.Lock()
				defer mutex.Unlock()

				var found bool
				for _, c := range connIDToCounter {
					if c.connID == connID {
						c.bytes += l
						found = true
						break
					}
				}
				if !found {
					connIDToCounter = append(connIDToCounter, &connIDCounter{connID: connID, bytes: l})
				}
			}
			return 2 * time.Millisecond
		},
	}
	require.NoError(t, proxy.Start())
	defer proxy.Close()

	transfer0RTTData(t, ln, proxy.LocalAddr(), clientConf, nil, GeneratePRData(5000)) // ~5 packets

	mutex.Lock()
	defer mutex.Unlock()

	require.Len(t, connIDToCounter, 2)
	require.InDelta(t, 5000+100 /* framing overhead */, int(connIDToCounter[0].bytes), 100) // the FIN bit might be sent extra
	require.InDelta(t, int(connIDToCounter[0].bytes), int(connIDToCounter[1].bytes), 20)
	zeroRTTPackets := counter.getRcvd0RTTPacketNumbers()
	require.GreaterOrEqual(t, len(zeroRTTPackets), 5)
	require.GreaterOrEqual(t, zeroRTTPackets[0], protocol.PacketNumber(5))
}

func Test0RTTWithIncreasedStreamLimit(t *testing.T) {
	rtt := scaleDuration(10 * time.Millisecond)
	const maxStreams = 1
	tlsConf := getTLSConfig()
	clientConf := dialAndReceiveTicket(t, rtt, tlsConf, getQuicConfig(&quic.Config{Allow0RTT: true, MaxIncomingUniStreams: maxStreams}), nil)

	ln, err := quic.ListenEarly(
		newUPDConnLocalhost(t),
		tlsConf,
		getQuicConfig(&quic.Config{Allow0RTT: true, MaxIncomingUniStreams: maxStreams + 1}),
	)
	require.NoError(t, err)
	defer ln.Close()

	proxy, counter := runCountingProxyAndCount0RTTPackets(t, ln.Addr().(*net.UDPAddr).Port, rtt)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	conn, err := quic.DialEarly(
		ctx,
		newUPDConnLocalhost(t),
		proxy.LocalAddr(),
		clientConf,
		getQuicConfig(nil),
	)
	require.NoError(t, err)
	require.False(t, conn.ConnectionState().TLS.HandshakeComplete)
	str, err := conn.OpenUniStream()
	require.NoError(t, err)
	_, err = str.Write([]byte("foobar"))
	require.NoError(t, err)
	require.NoError(t, str.Close())
	// the client remembers the old limit and refuses to open a new stream
	_, err = conn.OpenUniStream()
	require.Error(t, err)
	require.Contains(t, err.Error(), "too many open streams")

	// after handshake completion, the new limit applies
	select {
	case <-conn.HandshakeComplete():
	case <-time.After(time.Second):
		t.Fatal("handshake did not complete in time")
	}
	_, err = conn.OpenUniStream()
	require.NoError(t, err)
	require.True(t, conn.ConnectionState().Used0RTT)
	require.NoError(t, conn.CloseWithError(0, ""))

	require.NotZero(t, counter.Load())
}

func check0RTTRejected(t *testing.T,
	ln *quic.EarlyListener,
	addr net.Addr,
	conf *tls.Config,
	sendData bool,
) (clientConn, serverConn quic.Connection) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	conn, err := quic.DialEarly(ctx, newUPDConnLocalhost(t), addr, conf, getQuicConfig(nil))
	require.NoError(t, err)
	require.False(t, conn.ConnectionState().TLS.HandshakeComplete)
	if sendData {
		str, err := conn.OpenUniStream()
		require.NoError(t, err)
		_, err = str.Write(make([]byte, 3000))
		require.NoError(t, err)
		require.NoError(t, str.Close())
	}

	select {
	case <-conn.HandshakeComplete():
	case <-time.After(time.Second):
		t.Fatal("handshake did not complete in time")
	}
	require.False(t, conn.ConnectionState().Used0RTT)

	// make sure the server doesn't process the data
	ctx, cancel = context.WithTimeout(context.Background(), scaleDuration(50*time.Millisecond))
	defer cancel()
	serverConn, err = ln.Accept(ctx)
	require.NoError(t, err)
	require.False(t, serverConn.ConnectionState().Used0RTT)
	if sendData {
		_, err = serverConn.AcceptUniStream(ctx)
		require.Equal(t, context.DeadlineExceeded, err)
	}

	ctx, cancel = context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	nextConn, err := conn.NextConnection(ctx)
	require.NoError(t, err)
	require.True(t, nextConn.ConnectionState().TLS.HandshakeComplete)
	require.False(t, nextConn.ConnectionState().Used0RTT)
	return nextConn, serverConn
}

func Test0RTTRejectedOnStreamLimitDecrease(t *testing.T) {
	const rtt = 5 * time.Millisecond

	const (
		maxBidiStreams    = 42
		maxUniStreams     = 10
		newMaxBidiStreams = maxBidiStreams - 1
		newMaxUniStreams  = maxUniStreams - 1
	)

	tlsConf := getTLSConfig()
	clientConf := dialAndReceiveTicket(t,
		rtt,
		tlsConf,
		getQuicConfig(&quic.Config{
			Allow0RTT:             true,
			MaxIncomingStreams:    maxBidiStreams,
			MaxIncomingUniStreams: maxUniStreams,
		}),
		nil,
	)

	counter, tracer := newPacketTracer()
	ln, err := quic.ListenEarly(
		newUPDConnLocalhost(t),
		tlsConf,
		getQuicConfig(&quic.Config{
			Allow0RTT:             true,
			MaxIncomingStreams:    newMaxBidiStreams,
			MaxIncomingUniStreams: newMaxUniStreams,
			Tracer:                newTracer(tracer),
		}),
	)
	require.NoError(t, err)
	defer ln.Close()
	proxy, num0RTT := runCountingProxyAndCount0RTTPackets(t, ln.Addr().(*net.UDPAddr).Port, rtt)

	conn, serverConn := check0RTTRejected(t, ln, proxy.LocalAddr(), clientConf, true)
	defer conn.CloseWithError(0, "")

	// It should now be possible to open new bidirectional streams up to the new limit...
	for i := 0; i < newMaxBidiStreams; i++ {
		_, err = conn.OpenStream()
		require.NoError(t, err)
	}
	// ... but not beyond it.
	_, err = conn.OpenStream()
	require.Error(t, err)
	require.Contains(t, err.Error(), "too many open streams")

	// It should now be possible to open new unidirectional streams up to the new limit...
	for i := 0; i < newMaxUniStreams; i++ {
		_, err = conn.OpenUniStream()
		require.NoError(t, err)
	}
	// ... but not beyond it.
	_, err = conn.OpenUniStream()
	require.Error(t, err)
	require.Contains(t, err.Error(), "too many open streams")

	serverConn.CloseWithError(0, "")
	// The client should send 0-RTT packets, but the server doesn't process them.
	n := num0RTT.Load()
	t.Logf("sent %d 0-RTT packets", n)
	require.NotZero(t, n)
	require.Empty(t, counter.getRcvd0RTTPacketNumbers())
}

func Test0RTTRejectedOnConnectionWindowDecrease(t *testing.T) {
	const rtt = 5 * time.Millisecond

	const (
		connFlowControlWindow    = 100
		newConnFlowControlWindow = connFlowControlWindow - 1
	)

	tlsConf := getTLSConfig()
	clientConf := dialAndReceiveTicket(t,
		rtt,
		tlsConf,
		getQuicConfig(&quic.Config{
			Allow0RTT:                      true,
			InitialConnectionReceiveWindow: connFlowControlWindow,
		}),
		nil,
	)

	ln, err := quic.ListenEarly(
		newUPDConnLocalhost(t),
		tlsConf,
		getQuicConfig(&quic.Config{
			Allow0RTT:                      true,
			InitialConnectionReceiveWindow: newConnFlowControlWindow,
		}),
	)
	require.NoError(t, err)
	defer ln.Close()
	proxy, _ := runCountingProxyAndCount0RTTPackets(t, ln.Addr().(*net.UDPAddr).Port, rtt)

	conn, serverConn := check0RTTRejected(t, ln, proxy.LocalAddr(), clientConf, false)
	defer conn.CloseWithError(0, "")
	defer serverConn.CloseWithError(0, "")

	str, err := conn.OpenStream()
	require.NoError(t, err)
	str.SetWriteDeadline(time.Now().Add(scaleDuration(50 * time.Millisecond)))
	n, err := str.Write(make([]byte, 2000))
	require.ErrorIs(t, err, os.ErrDeadlineExceeded)
	require.Equal(t, newConnFlowControlWindow, n)

	// make sure that only 99 bytes were received
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	serverStr, err := serverConn.AcceptStream(ctx)
	require.NoError(t, err)
	serverStr.SetReadDeadline(time.Now().Add(scaleDuration(50 * time.Millisecond)))
	n, err = io.ReadFull(serverStr, make([]byte, newConnFlowControlWindow))
	require.NoError(t, err)
	require.Equal(t, newConnFlowControlWindow, n)
	_, err = serverStr.Read([]byte{0})
	require.ErrorIs(t, err, os.ErrDeadlineExceeded)
}

func Test0RTTRejectedOnALPNChanged(t *testing.T) {
	const rtt = 5 * time.Millisecond
	tlsConf := getTLSConfig()
	clientConf := dialAndReceiveTicket(t, rtt, tlsConf, getQuicConfig(&quic.Config{Allow0RTT: true}), nil)

	// switch to different ALPN on the server side
	tlsConf.NextProtos = []string{"new-alpn"}
	// Append to the client's ALPN.
	// crypto/tls will attempt to resume with the ALPN from the original connection
	clientConf.NextProtos = append(clientConf.NextProtos, "new-alpn")
	counter, tracer := newPacketTracer()
	ln, err := quic.ListenEarly(
		newUPDConnLocalhost(t),
		tlsConf,
		getQuicConfig(&quic.Config{
			Allow0RTT: true,
			Tracer:    newTracer(tracer),
		}),
	)
	require.NoError(t, err)
	defer ln.Close()
	proxy, num0RTTPackets := runCountingProxyAndCount0RTTPackets(t, ln.Addr().(*net.UDPAddr).Port, rtt)

	conn, serverConn := check0RTTRejected(t, ln, proxy.LocalAddr(), clientConf, true)
	defer conn.CloseWithError(0, "")
	defer serverConn.CloseWithError(0, "")

	require.Equal(t, "new-alpn", conn.ConnectionState().TLS.NegotiatedProtocol)

	serverConn.CloseWithError(0, "")
	// The client should send 0-RTT packets, but the server doesn't process them.
	num0RTT := num0RTTPackets.Load()
	t.Logf("Sent %d 0-RTT packets.", num0RTT)
	require.NotZero(t, num0RTT)
	require.Empty(t, counter.getRcvd0RTTPacketNumbers())
}

func Test0RTTRejectedWhenDisabled(t *testing.T) {
	const rtt = 5 * time.Millisecond
	tlsConf := getTLSConfig()
	clientConf := dialAndReceiveTicket(t, rtt, tlsConf, getQuicConfig(&quic.Config{Allow0RTT: true}), nil)

	counter, tracer := newPacketTracer()
	ln, err := quic.ListenEarly(
		newUPDConnLocalhost(t),
		tlsConf,
		getQuicConfig(&quic.Config{
			Allow0RTT: false,
			Tracer:    newTracer(tracer),
		}),
	)
	require.NoError(t, err)
	defer ln.Close()
	proxy, num0RTTPackets := runCountingProxyAndCount0RTTPackets(t, ln.Addr().(*net.UDPAddr).Port, rtt)

	conn, serverConn := check0RTTRejected(t, ln, proxy.LocalAddr(), clientConf, true)
	defer conn.CloseWithError(0, "")

	serverConn.CloseWithError(0, "")
	// The client should send 0-RTT packets, but the server doesn't process them.
	num0RTT := num0RTTPackets.Load()
	t.Logf("Sent %d 0-RTT packets.", num0RTT)
	require.NotZero(t, num0RTT)
	require.Empty(t, counter.getRcvd0RTTPacketNumbers())
}

func Test0RTTRejectedOnDatagramsDisabled(t *testing.T) {
	const rtt = 5 * time.Millisecond
	tlsConf := getTLSConfig()
	clientConf := dialAndReceiveTicket(t, rtt, tlsConf, getQuicConfig(&quic.Config{Allow0RTT: true, EnableDatagrams: true}), nil)

	counter, tracer := newPacketTracer()
	ln, err := quic.ListenEarly(
		newUPDConnLocalhost(t),
		tlsConf,
		getQuicConfig(&quic.Config{
			Allow0RTT:       true,
			EnableDatagrams: false,
			Tracer:          newTracer(tracer),
		}),
	)
	require.NoError(t, err)
	defer ln.Close()
	proxy, num0RTTPackets := runCountingProxyAndCount0RTTPackets(t, ln.Addr().(*net.UDPAddr).Port, rtt)

	conn, serverConn := check0RTTRejected(t, ln, proxy.LocalAddr(), clientConf, true)
	defer conn.CloseWithError(0, "")
	require.False(t, conn.ConnectionState().SupportsDatagrams)

	serverConn.CloseWithError(0, "")
	// The client should send 0-RTT packets, but the server doesn't process them.
	num0RTT := num0RTTPackets.Load()
	t.Logf("Sent %d 0-RTT packets.", num0RTT)
	require.NotZero(t, num0RTT)
	require.Empty(t, counter.getRcvd0RTTPacketNumbers())
}

type metadataClientSessionCache struct {
	toAdd    []byte
	restored func([]byte)

	cache tls.ClientSessionCache
}

func (m metadataClientSessionCache) Get(key string) (*tls.ClientSessionState, bool) {
	session, ok := m.cache.Get(key)
	if !ok || session == nil {
		return session, ok
	}
	ticket, state, err := session.ResumptionState()
	if err != nil {
		panic("failed to get resumption state: " + err.Error())
	}
	if len(state.Extra) != 2 { // ours, and the quic-go's
		panic("expected 2 state entries" + fmt.Sprintf("%v", state.Extra))
	}
	m.restored(state.Extra[1])
	// as of Go 1.23, this function never returns an error
	session, err = tls.NewResumptionState(ticket, state)
	if err != nil {
		panic("failed to create resumption state: " + err.Error())
	}
	return session, true
}

func (m metadataClientSessionCache) Put(key string, session *tls.ClientSessionState) {
	ticket, state, err := session.ResumptionState()
	if err != nil {
		panic("failed to get resumption state: " + err.Error())
	}
	state.Extra = append(state.Extra, m.toAdd)
	session, err = tls.NewResumptionState(ticket, state)
	if err != nil {
		panic("failed to create resumption state: " + err.Error())
	}
	m.cache.Put(key, session)
}

func Test0RTTWithSessionTicketData(t *testing.T) {
	t.Run("server", func(t *testing.T) {
		tlsConf := getTLSConfig()
		tlsConf.WrapSession = func(cs tls.ConnectionState, ss *tls.SessionState) ([]byte, error) {
			ss.Extra = append(ss.Extra, []byte("foobar"))
			return tlsConf.EncryptTicket(cs, ss)
		}
		stateChan := make(chan *tls.SessionState, 1)
		tlsConf.UnwrapSession = func(identity []byte, cs tls.ConnectionState) (*tls.SessionState, error) {
			state, err := tlsConf.DecryptTicket(identity, cs)
			if err != nil {
				panic("failed to decrypt ticket")
			}
			stateChan <- state
			return state, nil
		}
		clientConf := dialAndReceiveTicket(t, 0, tlsConf, getQuicConfig(&quic.Config{Allow0RTT: true}), nil)

		ln, err := quic.ListenEarly(newUPDConnLocalhost(t), tlsConf, getQuicConfig(&quic.Config{Allow0RTT: true}))
		require.NoError(t, err)
		defer ln.Close()

		transfer0RTTData(t, ln, ln.Addr(), clientConf, getQuicConfig(nil), PRData)

		select {
		case state := <-stateChan:
			require.Len(t, state.Extra, 2)
			require.Equal(t, []byte("foobar"), state.Extra[1])
		case <-time.After(time.Second):
			t.Fatal("timed out waiting for session state")
		}
	})

	t.Run("client", func(t *testing.T) {
		tlsConf := getTLSConfig()
		restoreChan := make(chan []byte, 1)
		clientConf := dialAndReceiveTicket(t,
			0,
			tlsConf,
			getQuicConfig(&quic.Config{Allow0RTT: true}),
			&metadataClientSessionCache{
				toAdd:    []byte("foobar"),
				restored: func(b []byte) { restoreChan <- b },
				cache:    tls.NewLRUClientSessionCache(100),
			},
		)

		ln, err := quic.ListenEarly(newUPDConnLocalhost(t), tlsConf, getQuicConfig(&quic.Config{Allow0RTT: true}))
		require.NoError(t, err)
		defer ln.Close()

		transfer0RTTData(t, ln, ln.Addr(), clientConf, getQuicConfig(nil), PRData)
		select {
		case b := <-restoreChan:
			require.Equal(t, []byte("foobar"), b)
		case <-time.After(time.Second):
			t.Fatal("timed out waiting for session state")
		}
	})
}

func Test0RTTPacketQueueing(t *testing.T) {
	rtt := scaleDuration(5 * time.Millisecond)
	tlsConf := getTLSConfig()
	clientConf := dialAndReceiveTicket(t, rtt, tlsConf, getQuicConfig(&quic.Config{Allow0RTT: true}), nil)

	counter, tracer := newPacketTracer()
	ln, err := quic.ListenEarly(
		newUPDConnLocalhost(t),
		tlsConf,
		getQuicConfig(&quic.Config{Allow0RTT: true, Tracer: newTracer(tracer)}),
	)
	require.NoError(t, err)
	defer ln.Close()

	proxy := quicproxy.Proxy{
		Conn:       newUPDConnLocalhost(t),
		ServerAddr: ln.Addr().(*net.UDPAddr),
		DelayPacket: func(dir quicproxy.Direction, data []byte) time.Duration {
			// delay the client's Initial by 1 RTT
			if dir == quicproxy.DirectionIncoming && wire.IsLongHeaderPacket(data[0]) && data[0]&0x30>>4 == 0 {
				return rtt * 3 / 2
			}
			return rtt / 2
		},
	}
	require.NoError(t, proxy.Start())
	defer proxy.Close()

	data := GeneratePRData(5000) // ~5 packets
	transfer0RTTData(t, ln, proxy.LocalAddr(), clientConf, getQuicConfig(nil), data)

	require.Equal(t, protocol.PacketTypeInitial, counter.getRcvdLongHeaderPackets()[0].hdr.Type)
	zeroRTTPackets := counter.getRcvd0RTTPacketNumbers()
	require.GreaterOrEqual(t, len(zeroRTTPackets), 5)
	// make sure the data wasn't retransmitted
	var dataSent protocol.ByteCount
	for _, p := range counter.getRcvdLongHeaderPackets() {
		for _, f := range p.frames {
			if sf, ok := f.(*logging.StreamFrame); ok {
				dataSent += sf.Length
			}
		}
	}
	for _, p := range counter.getRcvdShortHeaderPackets() {
		for _, f := range p.frames {
			if sf, ok := f.(*logging.StreamFrame); ok {
				dataSent += sf.Length
			}
		}
	}
	require.Less(t, int(dataSent), 6000)
	require.Equal(t, protocol.PacketNumber(0), zeroRTTPackets[0])
}

func Test0RTTDatagrams(t *testing.T) {
	const rtt = 5 * time.Millisecond
	tlsConf := getTLSConfig()
	clientTLSConf := dialAndReceiveTicket(t, rtt, tlsConf, getQuicConfig(&quic.Config{Allow0RTT: true, EnableDatagrams: true}), nil)

	counter, tracer := newPacketTracer()
	ln, err := quic.ListenEarly(
		newUPDConnLocalhost(t),
		tlsConf,
		getQuicConfig(&quic.Config{
			Allow0RTT:       true,
			EnableDatagrams: true,
			Tracer:          newTracer(tracer),
		}),
	)
	require.NoError(t, err)
	defer ln.Close()
	proxy, num0RTTPackets := runCountingProxyAndCount0RTTPackets(t, ln.Addr().(*net.UDPAddr).Port, rtt)

	msg := GeneratePRData(100)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	conn, err := quic.DialEarly(ctx, newUPDConnLocalhost(t), proxy.LocalAddr(), clientTLSConf, getQuicConfig(&quic.Config{EnableDatagrams: true}))
	require.NoError(t, err)
	defer conn.CloseWithError(0, "")
	require.True(t, conn.ConnectionState().SupportsDatagrams)
	require.NoError(t, conn.SendDatagram(msg))
	select {
	case <-conn.HandshakeComplete():
	case <-time.After(time.Second):
		t.Fatal("handshake did not complete in time")
	}

	serverConn, err := ln.Accept(ctx)
	require.NoError(t, err)
	rcvdMsg, err := serverConn.ReceiveDatagram(ctx)
	require.NoError(t, err)
	require.True(t, serverConn.ConnectionState().Used0RTT)
	require.Equal(t, msg, rcvdMsg)

	num0RTT := num0RTTPackets.Load()
	t.Logf("sent %d 0-RTT packets", num0RTT)
	require.NotZero(t, num0RTT)
	serverConn.CloseWithError(0, "")
	require.Len(t, counter.getRcvd0RTTPacketNumbers(), 1)
}
