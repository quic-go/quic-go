package self_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	mrand "math/rand"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	quicproxy "github.com/quic-go/quic-go/integrationtests/tools/proxy"
	"github.com/quic-go/quic-go/internal/wire"
	"github.com/quic-go/quic-go/quicvarint"

	"github.com/stretchr/testify/require"
)

func startDropTestListenerAndProxy(t *testing.T, rtt, timeout time.Duration, dropCallback quicproxy.DropCallback, doRetry bool, longCertChain bool) (_ *quic.Listener, proxyAddr net.Addr) {
	t.Helper()
	conf := getQuicConfig(&quic.Config{
		MaxIdleTimeout:          timeout,
		HandshakeIdleTimeout:    timeout,
		DisablePathMTUDiscovery: true,
	})
	var tlsConf *tls.Config
	if longCertChain {
		tlsConf = getTLSConfigWithLongCertChain()
	} else {
		tlsConf = getTLSConfig()
	}
	tr := &quic.Transport{
		Conn:                newUDPConnLocalhost(t),
		VerifySourceAddress: func(net.Addr) bool { return doRetry },
	}
	t.Cleanup(func() { tr.Close() })
	ln, err := tr.Listen(tlsConf, conf)
	require.NoError(t, err)
	t.Cleanup(func() { ln.Close() })

	proxy := quicproxy.Proxy{
		Conn:        newUDPConnLocalhost(t),
		ServerAddr:  ln.Addr().(*net.UDPAddr),
		DropPacket:  dropCallback,
		DelayPacket: func(quicproxy.Direction, net.Addr, net.Addr, []byte) time.Duration { return rtt / 2 },
	}
	require.NoError(t, proxy.Start())
	t.Cleanup(func() { proxy.Close() })
	return ln, proxy.LocalAddr()
}

func dropTestProtocolClientSpeaksFirst(t *testing.T, ln *quic.Listener, addr net.Addr, timeout time.Duration, data []byte) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	conn, err := quic.Dial(
		ctx,
		newUDPConnLocalhost(t),
		addr,
		getTLSClientConfig(),
		getQuicConfig(&quic.Config{
			MaxIdleTimeout:          timeout,
			HandshakeIdleTimeout:    timeout,
			DisablePathMTUDiscovery: true,
		}),
	)
	require.NoError(t, err)
	defer conn.CloseWithError(0, "")

	str, err := conn.OpenUniStream()
	require.NoError(t, err)
	errChan := make(chan error, 1)
	go func() {
		defer str.Close()
		_, err := str.Write(data)
		errChan <- err
	}()

	serverConn, err := ln.Accept(ctx)
	require.NoError(t, err)
	serverStr, err := serverConn.AcceptUniStream(ctx)
	require.NoError(t, err)
	b, err := io.ReadAll(&readerWithTimeout{Reader: serverStr, Timeout: timeout})
	require.NoError(t, err)
	require.Equal(t, b, data)
	serverConn.CloseWithError(0, "")
}

func dropTestProtocolServerSpeaksFirst(t *testing.T, ln *quic.Listener, addr net.Addr, timeout time.Duration, data []byte) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	conn, err := quic.Dial(
		ctx,
		newUDPConnLocalhost(t),
		addr,
		getTLSClientConfig(),
		getQuicConfig(&quic.Config{
			MaxIdleTimeout:          timeout,
			HandshakeIdleTimeout:    timeout,
			DisablePathMTUDiscovery: true,
		}),
	)
	require.NoError(t, err)

	errChan := make(chan error, 1)
	go func() {
		defer close(errChan)
		defer conn.CloseWithError(0, "")
		str, err := conn.AcceptUniStream(ctx)
		if err != nil {
			errChan <- err
			return
		}
		b, err := io.ReadAll(&readerWithTimeout{Reader: str, Timeout: timeout})
		if err != nil {
			errChan <- err
			return
		}
		if !bytes.Equal(b, data) {
			errChan <- fmt.Errorf("data mismatch: %x != %x", b, data)
			return
		}
	}()

	serverConn, err := ln.Accept(ctx)
	require.NoError(t, err)
	serverStr, err := serverConn.OpenUniStream()
	require.NoError(t, err)
	_, err = serverStr.Write(data)
	require.NoError(t, err)
	require.NoError(t, serverStr.Close())

	select {
	case err := <-errChan:
		require.NoError(t, err)
	case <-time.After(timeout):
		t.Fatal("server connection not closed")
	}

	select {
	case <-conn.Context().Done():
	case <-time.After(timeout):
		t.Fatal("server connection not closed")
	}
}

func dropTestProtocolNobodySpeaks(t *testing.T, ln *quic.Listener, addr net.Addr, timeout time.Duration) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	conn, err := quic.Dial(
		ctx,
		newUDPConnLocalhost(t),
		addr,
		getTLSClientConfig(),
		getQuicConfig(&quic.Config{
			MaxIdleTimeout:          timeout,
			HandshakeIdleTimeout:    timeout,
			DisablePathMTUDiscovery: true,
		}),
	)
	require.NoError(t, err)
	defer conn.CloseWithError(0, "")

	serverConn, err := ln.Accept(ctx)
	require.NoError(t, err)
	serverConn.CloseWithError(0, "")
}

func dropCallbackDropNthPacket(direction quicproxy.Direction, n int) quicproxy.DropCallback {
	var incoming, outgoing atomic.Int32
	return func(d quicproxy.Direction, _, _ net.Addr, packet []byte) bool {
		var p int32
		switch d {
		case quicproxy.DirectionIncoming:
			p = incoming.Add(1)
		case quicproxy.DirectionOutgoing:
			p = outgoing.Add(1)
		}
		return p == int32(n) && d.Is(direction)
	}
}

func dropCallbackDropOneThird(direction quicproxy.Direction) quicproxy.DropCallback {
	const maxSequentiallyDropped = 10
	var mx sync.Mutex
	var incoming, outgoing int
	return func(d quicproxy.Direction, _, _ net.Addr, _ []byte) bool {
		drop := mrand.Int63n(int64(3)) == 0

		mx.Lock()
		defer mx.Unlock()
		// never drop more than 10 consecutive packets
		if d.Is(quicproxy.DirectionIncoming) {
			if drop {
				incoming++
				if incoming > maxSequentiallyDropped {
					drop = false
				}
			}
			if !drop {
				incoming = 0
			}
		}
		if d.Is(quicproxy.DirectionOutgoing) {
			if drop {
				outgoing++
				if outgoing > maxSequentiallyDropped {
					drop = false
				}
			}
			if !drop {
				outgoing = 0
			}
		}
		return drop
	}
}

func TestHandshakeWithPacketLoss(t *testing.T) {
	data := GeneratePRData(5000)
	const timeout = 2 * time.Minute
	const rtt = 20 * time.Millisecond

	type dropPattern struct {
		name string
		fn   quicproxy.DropCallback
	}

	type serverConfig struct {
		longCertChain bool
		doRetry       bool
	}

	for _, direction := range []quicproxy.Direction{quicproxy.DirectionIncoming, quicproxy.DirectionOutgoing, quicproxy.DirectionBoth} {
		for _, dropPattern := range []dropPattern{
			{name: "drop 1st packet", fn: dropCallbackDropNthPacket(direction, 1)},
			{name: "drop 2nd packet", fn: dropCallbackDropNthPacket(direction, 2)},
			{name: "drop 1/3 of packets", fn: dropCallbackDropOneThird(direction)},
		} {
			t.Run(fmt.Sprintf("%s in %s direction", dropPattern.name, direction), func(t *testing.T) {
				for _, conf := range []serverConfig{
					{longCertChain: false, doRetry: true},
					{longCertChain: false, doRetry: false},
					{longCertChain: true, doRetry: false},
				} {
					t.Run(fmt.Sprintf("retry: %t", conf.doRetry), func(t *testing.T) {
						t.Run("client speaks first", func(t *testing.T) {
							ln, proxyAddr := startDropTestListenerAndProxy(t, rtt, timeout, dropPattern.fn, conf.doRetry, conf.longCertChain)
							dropTestProtocolClientSpeaksFirst(t, ln, proxyAddr, timeout, data)
						})

						t.Run("server speaks first", func(t *testing.T) {
							ln, proxyAddr := startDropTestListenerAndProxy(t, rtt, timeout, dropPattern.fn, conf.doRetry, conf.longCertChain)
							dropTestProtocolServerSpeaksFirst(t, ln, proxyAddr, timeout, data)
						})

						t.Run("nobody speaks", func(t *testing.T) {
							ln, proxyAddr := startDropTestListenerAndProxy(t, rtt, timeout, dropPattern.fn, conf.doRetry, conf.longCertChain)
							dropTestProtocolNobodySpeaks(t, ln, proxyAddr, timeout)
						})
					})
				}
			})
		}
	}
}

func TestPostQuantumClientHello(t *testing.T) {
	origAdditionalTransportParametersClient := wire.AdditionalTransportParametersClient
	t.Cleanup(func() { wire.AdditionalTransportParametersClient = origAdditionalTransportParametersClient })

	b := make([]byte, 2500) // the ClientHello will now span across 3 packets
	mrand.New(mrand.NewSource(time.Now().UnixNano())).Read(b)
	wire.AdditionalTransportParametersClient = map[uint64][]byte{
		// Avoid random collisions with the greased transport parameters.
		uint64(27+31*(1000+mrand.Int63()/31)) % quicvarint.Max: b,
	}

	ln, proxyPort := startDropTestListenerAndProxy(t, 10*time.Millisecond, 20*time.Second, dropCallbackDropOneThird(quicproxy.DirectionIncoming), false, false)
	dropTestProtocolClientSpeaksFirst(t, ln, proxyPort, time.Minute, GeneratePRData(5000))
}
