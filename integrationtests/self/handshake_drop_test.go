package self_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"math"
	mrand "math/rand/v2"
	"net"
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/internal/synctest"
	"github.com/quic-go/quic-go/testutils/simnet"

	"github.com/stretchr/testify/require"
)

func dropTestProtocolClientSpeaksFirst(t *testing.T, ln *quic.Listener, clientConn net.PacketConn, clientConf *tls.Config, timeout time.Duration, data []byte) *quic.Conn {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	conn, err := quic.Dial(
		ctx,
		clientConn,
		ln.Addr(),
		clientConf,
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

	return conn
}

func dropTestProtocolServerSpeaksFirst(t *testing.T, ln *quic.Listener, clientConn net.PacketConn, clientConf *tls.Config, timeout time.Duration, data []byte) *quic.Conn {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	conn, err := quic.Dial(
		ctx,
		clientConn,
		ln.Addr(),
		clientConf,
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

	return conn
}

func dropTestProtocolNobodySpeaks(t *testing.T, ln *quic.Listener, clientConn net.PacketConn, clientConf *tls.Config, timeout time.Duration, _ []byte) *quic.Conn {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	conn, err := quic.Dial(
		ctx,
		clientConn,
		ln.Addr(),
		clientConf,
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

	return conn
}

func dropCallbackDropNthPacket(dir direction, ns ...int) func(direction, simnet.Packet) bool {
	var incoming, outgoing atomic.Int32
	return func(d direction, p simnet.Packet) bool {
		switch d {
		case directionIncoming:
			c := incoming.Add(1)
			if d == dir || dir == directionBoth {
				return slices.Contains(ns, int(c))
			}
		case directionOutgoing:
			c := outgoing.Add(1)
			if dir == d || dir == directionBoth {
				return slices.Contains(ns, int(c))
			}
		}
		return false
	}
}

func dropCallbackDropOneThird(_ direction) func(direction, simnet.Packet) bool {
	const maxSequentiallyDropped = 10
	var mx sync.Mutex
	var incoming, outgoing atomic.Int32
	return func(d direction, p simnet.Packet) bool {
		drop := mrand.IntN(3) == 0

		mx.Lock()
		defer mx.Unlock()
		// never drop more than 10 consecutive packets
		if d == directionIncoming || d == directionBoth {
			if drop {
				n := incoming.Add(1)
				if n > maxSequentiallyDropped {
					drop = false
				}
			}
			if !drop {
				incoming.Store(0)
			}
		}
		if d == directionOutgoing || d == directionBoth {
			if drop {
				n := outgoing.Add(1)
				if n > maxSequentiallyDropped {
					drop = false
				}
			}
			if !drop {
				outgoing.Store(0)
			}
		}
		return drop
	}
}

func TestHandshakeWithPacketLoss(t *testing.T) {
	data := GeneratePRData(5000)
	const timeout = 2 * time.Minute
	const rtt = 20 * time.Millisecond

	type dropPattern string

	const (
		dropPatternDrop1stPacket         dropPattern = "drop 1st packet"
		dropPatternDropFirst3Packets     dropPattern = "drop first 3 packets"
		dropPatternDropOneThirdOfPackets dropPattern = "drop 1/3 of packets"
	)

	type testConfig struct {
		postQuantum   bool
		longCertChain bool
		doRetry       bool
	}

	for _, dir := range []direction{directionIncoming, directionOutgoing, directionBoth} {
		for _, pattern := range []dropPattern{
			dropPatternDrop1stPacket,
			dropPatternDropFirst3Packets,
			dropPatternDropOneThirdOfPackets,
		} {
			t.Run(fmt.Sprintf("%s in %s direction", pattern, dir), func(t *testing.T) {
				for _, conf := range []testConfig{
					{postQuantum: false, longCertChain: false, doRetry: true},
					{postQuantum: false, longCertChain: false, doRetry: false},
					{postQuantum: false, longCertChain: true, doRetry: false},
					{postQuantum: true, longCertChain: false, doRetry: false},
					{postQuantum: true, longCertChain: true, doRetry: false},
				} {
					for _, test := range []struct {
						name string
						fn   func(t *testing.T, ln *quic.Listener, clientConn net.PacketConn, clientConf *tls.Config, timeout time.Duration, data []byte) *quic.Conn
					}{
						{"client speaks first", dropTestProtocolClientSpeaksFirst},
						{"server speaks first", dropTestProtocolServerSpeaksFirst},
						{"nobody speaks", dropTestProtocolNobodySpeaks},
					} {
						t.Run(fmt.Sprintf("retry: %t/%s", conf.doRetry, test.name), func(t *testing.T) {
							synctest.Test(t, func(t *testing.T) {
								clientAddr := &net.UDPAddr{IP: net.ParseIP("1.0.0.1"), Port: 9001}
								serverAddr := &net.UDPAddr{IP: net.ParseIP("1.0.0.2"), Port: 9002}
								var fn func(direction, simnet.Packet) bool
								switch pattern {
								case dropPatternDrop1stPacket:
									fn = dropCallbackDropNthPacket(dir, 1)
								case dropPatternDropFirst3Packets:
									fn = dropCallbackDropNthPacket(dir, 1, 2, 3)
								case dropPatternDropOneThirdOfPackets:
									fn = dropCallbackDropOneThird(dir)
								}
								var numDropped atomic.Int32
								n := &simnet.Simnet{
									Router: &directionAwareDroppingRouter{
										ClientAddr: clientAddr,
										ServerAddr: serverAddr,
										Drop: func(d direction, p simnet.Packet) bool {
											drop := fn(d, p)
											if drop {
												numDropped.Add(1)
											}
											return drop
										},
									},
								}
								settings := simnet.NodeBiDiLinkSettings{
									Downlink: simnet.LinkSettings{BitsPerSecond: math.MaxInt, Latency: rtt / 4},
									Uplink:   simnet.LinkSettings{BitsPerSecond: math.MaxInt, Latency: rtt / 4},
								}
								clientConn := n.NewEndpoint(clientAddr, settings)
								defer clientConn.Close()
								serverConn := n.NewEndpoint(serverAddr, settings)
								defer serverConn.Close()
								require.NoError(t, n.Start())
								defer n.Close()

								var tlsConf *tls.Config
								if conf.longCertChain {
									tlsConf = getTLSConfigWithLongCertChain()
								} else {
									tlsConf = getTLSConfig()
								}
								clientConf := getTLSClientConfig()
								if !conf.postQuantum {
									clientConf.CurvePreferences = []tls.CurveID{tls.CurveP384}
								}

								tr := &quic.Transport{
									Conn:                serverConn,
									VerifySourceAddress: func(net.Addr) bool { return conf.doRetry },
								}
								defer tr.Close()

								ln, err := tr.Listen(
									tlsConf,
									getQuicConfig(&quic.Config{
										MaxIdleTimeout:          timeout,
										HandshakeIdleTimeout:    timeout,
										DisablePathMTUDiscovery: true,
									}),
								)
								require.NoError(t, err)
								defer ln.Close()

								conn := test.fn(t, ln, clientConn, clientConf, timeout, data)
								if !strings.HasPrefix(runtime.Version(), "go1.24") {
									curveID := getCurveID(conn.ConnectionState().TLS)
									if conf.postQuantum {
										require.Equal(t, tls.X25519MLKEM768, curveID)
									} else {
										require.Equal(t, tls.CurveP384, curveID)
									}
								}

								if pattern != dropPatternDropOneThirdOfPackets {
									require.NotZero(t, numDropped.Load())
								}
								t.Logf("dropped %d packets", numDropped.Load())
							})
						})
					}
				}
			})
		}
	}
}
