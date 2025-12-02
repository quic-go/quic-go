package self_test

import (
	"bytes"
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
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/synctest"
	"github.com/quic-go/quic-go/internal/wire"
	"github.com/quic-go/quic-go/qlog"
	"github.com/quic-go/quic-go/qlogwriter"
	"github.com/quic-go/quic-go/testutils/simnet"

	"github.com/stretchr/testify/require"
)

type zeroRTTCountingRouter struct {
	simnet.Router
	counter atomic.Uint32
}

var _ simnet.Router = &zeroRTTCountingRouter{}

func (r *zeroRTTCountingRouter) SendPacket(p simnet.Packet) error {
	if contains0RTTPacket(p.Data) {
		r.counter.Add(1)
	}
	return r.Router.SendPacket(p)
}

func (r *zeroRTTCountingRouter) Num0RTTPackets() int {
	return int(r.counter.Load())
}

func dialAndReceiveTicket(t *testing.T, ln *quic.EarlyListener, clientConn net.PacketConn, sessionCache tls.ClientSessionCache) (clientTLSConf *tls.Config) {
	t.Helper()

	clientTLSConf = getTLSClientConfig()
	puts := make(chan string, 100)
	cache := sessionCache
	if cache == nil {
		cache = tls.NewLRUClientSessionCache(100)
	}
	clientTLSConf.ClientSessionCache = newClientSessionCache(cache, nil, puts)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	tr := &quic.Transport{Conn: clientConn}
	defer tr.Close()
	conn, err := tr.Dial(ctx, ln.Addr(), clientTLSConf, getQuicConfig(nil))
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
	clientPacketConn net.PacketConn,
	clientTLSConf *tls.Config,
	clientConf *quic.Config,
	testdata []byte, // data to transfer
) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	tr := &quic.Transport{Conn: clientPacketConn}
	defer tr.Close()
	conn, err := tr.DialEarly(ctx, ln.Addr(), clientTLSConf, clientConf)
	require.NoError(t, err)

	errChan := make(chan error, 1)
	serverConnChan := make(chan *quic.Conn, 1)
	go func() {
		defer close(errChan)
		conn, err := ln.Accept(context.Background())
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

	clientErrChan := make(chan error, 1)
	go func() {
		defer close(clientErrChan)
		// wait for the EOF from the server to arrive before closing the conn
		data, err := io.ReadAll(str)
		if err != nil {
			t.Error(err)
			clientErrChan <- err
			return
		}
		if !bytes.Equal(testdata, data) {
			clientErrChan <- fmt.Errorf("data mismatch")
		}
	}()

	_, err = str.Write(testdata)
	require.NoError(t, err)
	require.NoError(t, str.Close())
	select {
	case <-conn.HandshakeComplete():
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for handshake to complete")
	}

	select {
	case err := <-clientErrChan:
		require.NoError(t, err)
	case <-time.After(time.Hour):
		t.Fatal("timeout waiting for client to read data")
	}

	select {
	case err := <-errChan:
		require.NoError(t, err)
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for server to process data")
	}

	var serverConn *quic.Conn
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
	synctest.Test(t, func(t *testing.T) {
		const rtt = 50 * time.Millisecond

		router := &zeroRTTCountingRouter{Router: &simnet.PerfectRouter{}}
		clientConn, serverConn, closeFn := newSimnetLinkWithRouter(t, rtt, router)
		defer closeFn(t)

		tlsConf := getTLSConfig()
		tr := &quic.Transport{Conn: serverConn}
		counter, tracer := newPacketTracer()
		defer tr.Close()
		ln, err := tr.ListenEarly(
			tlsConf,
			getQuicConfig(&quic.Config{
				Allow0RTT: true,
				Tracer:    func(context.Context, bool, quic.ConnectionID) qlogwriter.Trace { return tracer },
			}),
		)
		require.NoError(t, err)
		defer ln.Close()

		clientTLSConf := dialAndReceiveTicket(t, ln, clientConn, nil)

		time.Sleep(time.Hour)
		synctest.Wait()

		transfer0RTTData(t, ln, clientConn, clientTLSConf, getQuicConfig(nil), PRData)

		num0RTT := router.Num0RTTPackets()
		t.Logf("sent %d 0-RTT packets", num0RTT)
		zeroRTTPackets := counter.getRcvd0RTTPacketNumbers()
		t.Logf("received %d 0-RTT packets", len(zeroRTTPackets))
		require.Greater(t, num0RTT, 20)
		require.Contains(t, zeroRTTPackets, protocol.PacketNumber(0))
	})
}

func Test0RTTDisabledOnDial(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const rtt = 25 * time.Millisecond

		router := &zeroRTTCountingRouter{Router: &simnet.PerfectRouter{}}
		clientConn, serverConn, closeFn := newSimnetLinkWithRouter(t, rtt, router)
		defer closeFn(t)

		tlsConf := getTLSConfig()
		tr := &quic.Transport{Conn: serverConn}
		defer tr.Close()
		ln, err := tr.ListenEarly(tlsConf, getQuicConfig(&quic.Config{Allow0RTT: true}))
		require.NoError(t, err)
		defer ln.Close()
		clientTLSConf := dialAndReceiveTicket(t, ln, clientConn, nil)

		time.Sleep(time.Hour)
		synctest.Wait()

		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		conn, err := quic.Dial(ctx, clientConn, serverConn.LocalAddr(), clientTLSConf, getQuicConfig(nil))
		require.NoError(t, err)
		// session Resumption is enabled at the TLS layer, but not 0-RTT at the QUIC layer
		require.True(t, conn.ConnectionState().TLS.DidResume)
		require.False(t, conn.ConnectionState().Used0RTT)
		conn.CloseWithError(0, "")

		require.Zero(t, router.Num0RTTPackets())
	})
}

func Test0RTTWaitForHandshakeCompletion(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const rtt = 50 * time.Millisecond

		router := &zeroRTTCountingRouter{Router: &simnet.PerfectRouter{}}
		clientConn, serverConn, closeFn := newSimnetLinkWithRouter(t, rtt, router)
		defer closeFn(t)

		tlsConf := getTLSConfig()
		tr := &quic.Transport{Conn: serverConn}
		defer tr.Close()
		counter, tracer := newPacketTracer()
		ln, err := tr.ListenEarly(
			tlsConf,
			getQuicConfig(&quic.Config{
				Allow0RTT: true,
				Tracer:    func(context.Context, bool, quic.ConnectionID) qlogwriter.Trace { return tracer },
			}),
		)
		require.NoError(t, err)
		defer ln.Close()
		clientTLSConf := dialAndReceiveTicket(t, ln, clientConn, nil)

		zeroRTTData := GeneratePRData(5 << 10)
		oneRTTData := PRData

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
			clientConn,
			serverConn.LocalAddr(),
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
			if p.hdr.PacketType != qlog.PacketType0RTT {
				continue
			}
			for _, f := range p.frames {
				sf, ok := f.Frame.(*qlog.StreamFrame)
				if !ok {
					continue
				}
				num0RTT++
				require.Equal(t, firstStr.StreamID(), sf.StreamID)
			}
		}
		t.Logf("received %d STREAM frames in 0-RTT packets", num0RTT)
		require.NotZero(t, num0RTT)
	})
}

func Test0RTTDataLoss(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const rtt = 5 * time.Millisecond
		tlsConf := getTLSConfig()

		var num0RTTPackets, numDropped atomic.Uint32
		router := &droppingRouter{
			Drop: func(p simnet.Packet) bool {
				if !wire.IsLongHeaderPacket(p.Data[0]) {
					return false
				}
				hdr, _, _, _ := wire.ParsePacket(p.Data)
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
		clientConn, serverConn, closeFn := newSimnetLinkWithRouter(t, rtt, router)
		defer closeFn(t)

		tr := &quic.Transport{Conn: serverConn}
		defer tr.Close()
		counter, tracer := newPacketTracer()
		ln, err := tr.ListenEarly(
			tlsConf,
			getQuicConfig(&quic.Config{
				Allow0RTT: true,
				Tracer:    func(context.Context, bool, quic.ConnectionID) qlogwriter.Trace { return tracer },
			}),
		)
		require.NoError(t, err)
		defer ln.Close()
		clientTLSConf := dialAndReceiveTicket(t, ln, clientConn, nil)

		transfer0RTTData(t, ln, clientConn, clientTLSConf, getQuicConfig(nil), PRData)

		num0RTT := num0RTTPackets.Load()
		dropped := numDropped.Load()
		t.Logf("sent %d 0-RTT packets, dropped %d of those.", num0RTT, dropped)
		require.NotZero(t, num0RTT)
		require.NotZero(t, dropped)
		require.NotEmpty(t, counter.getRcvd0RTTPacketNumbers())
	})
}

func Test0RTTRetransmitOnRetry(t *testing.T) {
	t.Run("no retry", func(t *testing.T) {
		test0RTTRetransmitOnRetry(t, false)
	})
	t.Run("with retry", func(t *testing.T) {
		test0RTTRetransmitOnRetry(t, true)
	})
}

func test0RTTRetransmitOnRetry(t *testing.T, useRetry bool) {
	synctest.Test(t, func(t *testing.T) {
		const rtt = 5 * time.Millisecond
		tlsConf := getTLSConfig()

		type connIDCounter struct {
			connID protocol.ConnectionID
			bytes  protocol.ByteCount
		}
		var mutex sync.Mutex
		var connIDToCounter []*connIDCounter
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

		router := &zeroRTTCountingRouter{
			Router: &callbackRouter{
				Router: &zeroRTTCountingRouter{Router: &simnet.PerfectRouter{}},
				OnSendPacket: func(p simnet.Packet) {
					if l := countZeroRTTBytes(p.Data); l > 0 {
						mutex.Lock()
						defer mutex.Unlock()

						connID, err := wire.ParseConnectionID(p.Data, 0)
						if err != nil {
							panic("failed to parse connection ID")
						}
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
				},
			},
		}
		clientConn, serverConn, closeFn := newSimnetLinkWithRouter(t, rtt, router)
		defer closeFn(t)

		tr := &quic.Transport{
			Conn:                serverConn,
			VerifySourceAddress: func(net.Addr) bool { return useRetry },
		}
		defer tr.Close()
		counter, tracer := newPacketTracer()
		ln, err := tr.ListenEarly(
			tlsConf,
			getQuicConfig(&quic.Config{
				Allow0RTT: true,
				Tracer:    func(context.Context, bool, quic.ConnectionID) qlogwriter.Trace { return tracer },
			}),
		)
		require.NoError(t, err)
		defer ln.Close()
		clientTLSConf := dialAndReceiveTicket(t, ln, clientConn, nil)
		require.Empty(t, connIDToCounter)

		transfer0RTTData(t, ln, clientConn, clientTLSConf, getQuicConfig(nil), GeneratePRData(5000)) // ~5 packets

		mutex.Lock()
		defer mutex.Unlock()

		if !useRetry {
			require.Len(t, connIDToCounter, 1)
			return
		}

		require.Len(t, connIDToCounter, 2)
		require.InDelta(t, 5000+100 /* framing overhead */, int(connIDToCounter[0].bytes), 100) // the FIN bit might be sent extra
		require.InDelta(t, int(connIDToCounter[0].bytes), int(connIDToCounter[1].bytes), 20)
		zeroRTTPackets := counter.getRcvd0RTTPacketNumbers()
		require.GreaterOrEqual(t, len(zeroRTTPackets), 5)
		require.GreaterOrEqual(t, zeroRTTPackets[0], protocol.PacketNumber(5))
	})
}

func Test0RTTWithIncreasedStreamLimit(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const rtt = 10 * time.Millisecond

		router := &zeroRTTCountingRouter{Router: &simnet.PerfectRouter{}}
		clientConn, serverConn, closeFn := newSimnetLinkWithRouter(t, rtt, router)
		defer closeFn(t)

		tlsConf := getTLSConfig()
		tr := &quic.Transport{Conn: serverConn}
		defer tr.Close()
		ln, err := tr.ListenEarly(tlsConf, getQuicConfig(&quic.Config{Allow0RTT: true, MaxIncomingUniStreams: 1}))
		require.NoError(t, err)
		clientTLSConf := dialAndReceiveTicket(t, ln, clientConn, nil)
		require.Zero(t, router.Num0RTTPackets())
		require.NoError(t, ln.Close())

		time.Sleep(time.Hour)
		synctest.Wait()

		ln, err = tr.ListenEarly(tlsConf, getQuicConfig(&quic.Config{Allow0RTT: true, MaxIncomingUniStreams: 2}))
		require.NoError(t, err)
		defer ln.Close()

		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		conn, err := quic.DialEarly(
			ctx,
			clientConn,
			ln.Addr(),
			clientTLSConf,
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
		require.ErrorIs(t, err, &quic.StreamLimitReachedError{})

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

		require.NotZero(t, router.Num0RTTPackets())
	})
}

func check0RTTRejected(t *testing.T,
	ln *quic.EarlyListener,
	clientPacketConn net.PacketConn,
	addr net.Addr,
	conf *tls.Config,
	sendData bool,
) (clientConn, serverConn *quic.Conn) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	conn, err := quic.DialEarly(ctx, clientPacketConn, addr, conf, getQuicConfig(nil))
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
	ctx, cancel = context.WithTimeout(context.Background(), time.Second)
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
	synctest.Test(t, func(t *testing.T) {
		const rtt = 5 * time.Millisecond

		const (
			maxBidiStreams    = 42
			maxUniStreams     = 10
			newMaxBidiStreams = maxBidiStreams - 1
			newMaxUniStreams  = maxUniStreams - 1
		)

		router := &zeroRTTCountingRouter{Router: &simnet.PerfectRouter{}}
		clientConn, serverConn, closeFn := newSimnetLinkWithRouter(t, rtt, router)
		defer closeFn(t)

		tlsConf := getTLSConfig()
		tr := &quic.Transport{Conn: serverConn}
		defer tr.Close()
		ln, err := tr.ListenEarly(
			tlsConf,
			getQuicConfig(&quic.Config{
				Allow0RTT:             true,
				MaxIncomingStreams:    maxBidiStreams,
				MaxIncomingUniStreams: maxUniStreams,
			}),
		)
		require.NoError(t, err)
		clientTLSConf := dialAndReceiveTicket(t, ln, clientConn, nil)
		require.NoError(t, ln.Close())

		time.Sleep(time.Hour)
		synctest.Wait()

		counter, tracer := newPacketTracer()
		ln, err = tr.ListenEarly(
			tlsConf,
			getQuicConfig(&quic.Config{
				Allow0RTT:             true,
				MaxIncomingStreams:    newMaxBidiStreams,
				MaxIncomingUniStreams: newMaxUniStreams,
				Tracer:                func(context.Context, bool, quic.ConnectionID) qlogwriter.Trace { return tracer },
			}),
		)
		require.NoError(t, err)
		defer ln.Close()

		conn, sconn := check0RTTRejected(t, ln, clientConn, ln.Addr(), clientTLSConf, true)
		defer conn.CloseWithError(0, "")

		// It should now be possible to open new bidirectional streams up to the new limit...
		for range newMaxBidiStreams {
			_, err = conn.OpenStream()
			require.NoError(t, err)
		}
		// ... but not beyond it.
		_, err = conn.OpenStream()
		require.ErrorIs(t, err, &quic.StreamLimitReachedError{})

		// It should now be possible to open new unidirectional streams up to the new limit...
		for range newMaxUniStreams {
			_, err = conn.OpenUniStream()
			require.NoError(t, err)
		}
		// ... but not beyond it.
		_, err = conn.OpenUniStream()
		require.ErrorIs(t, err, &quic.StreamLimitReachedError{})

		sconn.CloseWithError(0, "")
		// The client should send 0-RTT packets, but the server doesn't process them.
		n := router.Num0RTTPackets()
		t.Logf("sent %d 0-RTT packets", n)
		require.NotZero(t, n)
		require.Empty(t, counter.getRcvd0RTTPacketNumbers())
	})
}

func Test0RTTRejectedOnConnectionWindowDecrease(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const rtt = 5 * time.Millisecond

		const (
			connFlowControlWindow    = 100
			newConnFlowControlWindow = connFlowControlWindow - 1
		)

		router := &zeroRTTCountingRouter{Router: &simnet.PerfectRouter{}}
		clientConn, serverConn, closeFn := newSimnetLinkWithRouter(t, rtt, router)
		defer closeFn(t)

		tlsConf := getTLSConfig()
		tr := &quic.Transport{Conn: serverConn}
		defer tr.Close()
		ln, err := tr.ListenEarly(
			tlsConf,
			getQuicConfig(&quic.Config{
				Allow0RTT:                      true,
				InitialConnectionReceiveWindow: connFlowControlWindow,
			}),
		)
		require.NoError(t, err)
		clientTLSConf := dialAndReceiveTicket(t, ln, clientConn, nil)
		require.NoError(t, ln.Close())

		time.Sleep(time.Hour)
		synctest.Wait()

		ln, err = tr.ListenEarly(
			tlsConf,
			getQuicConfig(&quic.Config{
				Allow0RTT:                      true,
				InitialConnectionReceiveWindow: newConnFlowControlWindow,
			}),
		)
		require.NoError(t, err)

		conn, sconn := check0RTTRejected(t, ln, clientConn, ln.Addr(), clientTLSConf, false)
		defer conn.CloseWithError(0, "")
		defer sconn.CloseWithError(0, "")

		str, err := conn.OpenStream()
		require.NoError(t, err)
		str.SetWriteDeadline(time.Now().Add(time.Second))
		n, err := str.Write(make([]byte, 2000))
		require.ErrorIs(t, err, os.ErrDeadlineExceeded)
		require.Equal(t, newConnFlowControlWindow, n)

		// make sure that only 99 bytes were received
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		serverStr, err := sconn.AcceptStream(ctx)
		require.NoError(t, err)
		serverStr.SetReadDeadline(time.Now().Add(time.Second))
		n, err = io.ReadFull(serverStr, make([]byte, newConnFlowControlWindow))
		require.NoError(t, err)
		require.Equal(t, newConnFlowControlWindow, n)
		_, err = serverStr.Read([]byte{0})
		require.ErrorIs(t, err, os.ErrDeadlineExceeded)
	})
}

func Test0RTTRejectedOnALPNChanged(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const rtt = 5 * time.Millisecond

		router := &zeroRTTCountingRouter{Router: &simnet.PerfectRouter{}}
		clientConn, serverConn, closeFn := newSimnetLinkWithRouter(t, rtt, router)
		defer closeFn(t)

		tlsConf := getTLSConfig()
		tr := &quic.Transport{Conn: serverConn}
		defer tr.Close()
		ln, err := tr.ListenEarly(tlsConf, getQuicConfig(&quic.Config{Allow0RTT: true}))
		require.NoError(t, err)
		clientTLSConf := dialAndReceiveTicket(t, ln, clientConn, nil)
		require.NoError(t, ln.Close())

		time.Sleep(time.Hour)
		synctest.Wait()

		// switch to different ALPN on the server side
		tlsConf.NextProtos = []string{"new-alpn"}
		// Append to the client's ALPN.
		// crypto/tls will attempt to resume with the ALPN from the original connection
		clientTLSConf.NextProtos = append(clientTLSConf.NextProtos, "new-alpn")
		counter, tracer := newPacketTracer()
		ln, err = tr.ListenEarly(
			tlsConf,
			getQuicConfig(&quic.Config{
				Allow0RTT: true,
				Tracer:    func(context.Context, bool, quic.ConnectionID) qlogwriter.Trace { return tracer },
			}),
		)
		require.NoError(t, err)
		defer ln.Close()

		conn, sconn := check0RTTRejected(t, ln, clientConn, ln.Addr(), clientTLSConf, true)
		defer conn.CloseWithError(0, "")

		require.Equal(t, "new-alpn", conn.ConnectionState().TLS.NegotiatedProtocol)

		sconn.CloseWithError(0, "")
		// The client should send 0-RTT packets, but the server doesn't process them.
		num0RTT := router.Num0RTTPackets()
		t.Logf("Sent %d 0-RTT packets.", num0RTT)
		require.NotZero(t, num0RTT)
		require.Empty(t, counter.getRcvd0RTTPacketNumbers())
	})
}

func Test0RTTRejectedWhenDisabled(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const rtt = 5 * time.Millisecond
		router := &zeroRTTCountingRouter{Router: &simnet.PerfectRouter{}}
		clientConn, serverConn, closeFn := newSimnetLinkWithRouter(t, rtt, router)
		defer closeFn(t)

		tlsConf := getTLSConfig()
		tr := &quic.Transport{Conn: serverConn}
		defer tr.Close()
		ln, err := tr.ListenEarly(tlsConf, getQuicConfig(&quic.Config{Allow0RTT: true}))
		require.NoError(t, err)
		clientTLSConf := dialAndReceiveTicket(t, ln, clientConn, nil)
		require.NoError(t, ln.Close())

		time.Sleep(time.Hour)
		synctest.Wait()

		counter, tracer := newPacketTracer()
		ln, err = tr.ListenEarly(
			tlsConf,
			getQuicConfig(&quic.Config{
				Allow0RTT: false,
				Tracer:    func(context.Context, bool, quic.ConnectionID) qlogwriter.Trace { return tracer },
			}),
		)
		require.NoError(t, err)
		defer ln.Close()
		conn, sconn := check0RTTRejected(t, ln, clientConn, ln.Addr(), clientTLSConf, true)
		defer conn.CloseWithError(0, "")

		sconn.CloseWithError(0, "")
		// The client should send 0-RTT packets, but the server doesn't process them.
		num0RTT := router.Num0RTTPackets()
		t.Logf("Sent %d 0-RTT packets.", num0RTT)
		require.NotZero(t, num0RTT)
		require.Empty(t, counter.getRcvd0RTTPacketNumbers())
	})
}

func Test0RTTRejectedOnDatagramsDisabled(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const rtt = 5 * time.Millisecond
		router := &zeroRTTCountingRouter{Router: &simnet.PerfectRouter{}}
		clientConn, serverConn, closeFn := newSimnetLinkWithRouter(t, rtt, router)
		defer closeFn(t)

		tlsConf := getTLSConfig()
		tr := &quic.Transport{Conn: serverConn}
		defer tr.Close()
		ln, err := tr.ListenEarly(tlsConf, getQuicConfig(&quic.Config{Allow0RTT: true, EnableDatagrams: true}))
		require.NoError(t, err)
		clientTLSConf := dialAndReceiveTicket(t, ln, clientConn, nil)
		require.NoError(t, ln.Close())

		time.Sleep(time.Hour)
		synctest.Wait()

		counter, tracer := newPacketTracer()
		ln, err = tr.ListenEarly(
			tlsConf,
			getQuicConfig(&quic.Config{
				Allow0RTT:       true,
				EnableDatagrams: false,
				Tracer:          func(context.Context, bool, quic.ConnectionID) qlogwriter.Trace { return tracer },
			}),
		)
		require.NoError(t, err)
		defer ln.Close()
		conn, sconn := check0RTTRejected(t, ln, clientConn, ln.Addr(), clientTLSConf, true)
		defer conn.CloseWithError(0, "")
		require.False(t, conn.ConnectionState().SupportsDatagrams)

		sconn.CloseWithError(0, "")
		// The client should send 0-RTT packets, but the server doesn't process them.
		num0RTT := router.Num0RTTPackets()
		t.Logf("Sent %d 0-RTT packets.", num0RTT)
		require.NotZero(t, num0RTT)
		require.Empty(t, counter.getRcvd0RTTPacketNumbers())
	})
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
	const rtt = 5 * time.Millisecond

	t.Run("server", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			tlsConf := getTLSConfig()
			tlsConf.WrapSession = func(cs tls.ConnectionState, ss *tls.SessionState) ([]byte, error) {
				ss.Extra = append(ss.Extra, []byte("foobar"))
				return tlsConf.EncryptTicket(cs, ss)
			}
			router := &zeroRTTCountingRouter{Router: &simnet.PerfectRouter{}}
			clientConn, serverConn, closeFn := newSimnetLinkWithRouter(t, rtt, router)
			defer closeFn(t)

			tr := &quic.Transport{Conn: serverConn}
			defer tr.Close()
			ln, err := tr.ListenEarly(tlsConf, getQuicConfig(&quic.Config{Allow0RTT: true}))
			require.NoError(t, err)

			clientTLSConf := dialAndReceiveTicket(t, ln, clientConn, nil)
			stateChan := make(chan *tls.SessionState, 1)
			tlsConf.UnwrapSession = func(identity []byte, cs tls.ConnectionState) (*tls.SessionState, error) {
				state, err := tlsConf.DecryptTicket(identity, cs)
				if err != nil {
					panic("failed to decrypt ticket")
				}
				stateChan <- state
				return state, nil
			}

			transfer0RTTData(t, ln, clientConn, clientTLSConf, getQuicConfig(nil), PRData)

			select {
			case state := <-stateChan:
				require.Len(t, state.Extra, 2)
				require.Equal(t, []byte("foobar"), state.Extra[1])
			case <-time.After(time.Second):
				t.Fatal("timed out waiting for session state")
			}
		})
	})

	t.Run("client", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			router := &zeroRTTCountingRouter{Router: &simnet.PerfectRouter{}}
			clientConn, serverConn, closeFn := newSimnetLinkWithRouter(t, rtt, router)
			defer closeFn(t)

			tr := &quic.Transport{Conn: serverConn}
			defer tr.Close()
			ln, err := tr.ListenEarly(getTLSConfig(), getQuicConfig(&quic.Config{Allow0RTT: true}))
			require.NoError(t, err)
			defer ln.Close()

			restoreChan := make(chan []byte, 1)
			clientTLSConf := dialAndReceiveTicket(t,
				ln,
				clientConn,
				&metadataClientSessionCache{
					toAdd:    []byte("foobar"),
					restored: func(b []byte) { restoreChan <- b },
					cache:    tls.NewLRUClientSessionCache(100),
				},
			)

			transfer0RTTData(t, ln, clientConn, clientTLSConf, getQuicConfig(nil), PRData)
			select {
			case b := <-restoreChan:
				require.Equal(t, []byte("foobar"), b)
			case <-time.After(time.Second):
				t.Fatal("timed out waiting for session state")
			}
		})
	})
}

func Test0RTTPacketQueueing(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const rtt = 5 * time.Millisecond
		n := &simnet.Simnet{Router: &simnet.PerfectRouter{}}
		serverAddr := &net.UDPAddr{IP: net.ParseIP("1.0.0.2"), Port: 9002}
		settings := simnet.NodeBiDiLinkSettings{
			LatencyFunc: func(p simnet.Packet) time.Duration {
				if p.To.String() == serverAddr.String() {
					if wire.IsLongHeaderPacket(p.Data[0]) {
						hdr, _, _, err := wire.ParsePacket(p.Data)
						if err == nil && hdr.Type == protocol.PacketTypeInitial {
							return rtt * 3 / 2
						}
					}
				}
				return rtt / 2
			},
		}
		clientConn := n.NewEndpoint(&net.UDPAddr{IP: net.ParseIP("1.0.0.1"), Port: 9001}, settings)
		serverConn := n.NewEndpoint(serverAddr, settings)
		require.NoError(t, n.Start())
		defer func() {
			require.NoError(t, clientConn.Close())
			require.NoError(t, serverConn.Close())
			require.NoError(t, n.Close())
		}()

		tr := &quic.Transport{Conn: serverConn}
		defer tr.Close()
		counter, tracer := newPacketTracer()
		ln, err := tr.ListenEarly(
			getTLSConfig(),
			getQuicConfig(&quic.Config{
				Allow0RTT: true,
				Tracer:    func(context.Context, bool, quic.ConnectionID) qlogwriter.Trace { return tracer },
			}),
		)
		require.NoError(t, err)
		defer ln.Close()

		clientTLSConf := dialAndReceiveTicket(t, ln, clientConn, nil)

		data := GeneratePRData(5000) // ~5 packets
		transfer0RTTData(t, ln, clientConn, clientTLSConf, getQuicConfig(nil), data)

		require.Equal(t, qlog.PacketTypeInitial, counter.getRcvdLongHeaderPackets()[0].hdr.PacketType)
		zeroRTTPackets := counter.getRcvd0RTTPacketNumbers()
		require.GreaterOrEqual(t, len(zeroRTTPackets), 5)
		// make sure the data wasn't retransmitted
		var dataSent protocol.ByteCount
		for _, p := range counter.getRcvdLongHeaderPackets() {
			for _, f := range p.frames {
				if sf, ok := f.Frame.(*qlog.StreamFrame); ok {
					dataSent += protocol.ByteCount(sf.Length)
				}
			}
		}
		for _, p := range counter.getRcvdShortHeaderPackets() {
			for _, f := range p.frames {
				if sf, ok := f.Frame.(*qlog.StreamFrame); ok {
					dataSent += protocol.ByteCount(sf.Length)
				}
			}
		}
		require.Less(t, int(dataSent), 6000)
		require.Equal(t, protocol.PacketNumber(0), zeroRTTPackets[0])
	})
}

func Test0RTTDatagrams(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const rtt = 5 * time.Millisecond
		router := &zeroRTTCountingRouter{Router: &simnet.PerfectRouter{}}
		clientConn, serverConn, closeFn := newSimnetLinkWithRouter(t, rtt, router)
		defer closeFn(t)

		tr := &quic.Transport{Conn: serverConn}
		defer tr.Close()

		counter, tracer := newPacketTracer()
		ln, err := tr.ListenEarly(
			getTLSConfig(),
			getQuicConfig(&quic.Config{
				Allow0RTT:       true,
				EnableDatagrams: true,
				Tracer:          func(context.Context, bool, quic.ConnectionID) qlogwriter.Trace { return tracer },
			}),
		)
		require.NoError(t, err)
		defer ln.Close()

		clientTLSConf := dialAndReceiveTicket(t, ln, clientConn, nil)

		msg := GeneratePRData(100)
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		conn, err := quic.DialEarly(ctx,
			clientConn,
			ln.Addr(),
			clientTLSConf,
			getQuicConfig(&quic.Config{EnableDatagrams: true}),
		)
		require.NoError(t, err)
		defer conn.CloseWithError(0, "")
		require.True(t, conn.ConnectionState().SupportsDatagrams)
		require.NoError(t, conn.SendDatagram(msg))
		select {
		case <-conn.HandshakeComplete():
		case <-time.After(time.Second):
			t.Fatal("handshake did not complete in time")
		}

		sconn, err := ln.Accept(ctx)
		require.NoError(t, err)
		rcvdMsg, err := sconn.ReceiveDatagram(ctx)
		require.NoError(t, err)
		require.True(t, sconn.ConnectionState().Used0RTT)
		require.Equal(t, msg, rcvdMsg)

		num0RTT := router.Num0RTTPackets()
		t.Logf("sent %d 0-RTT packets", num0RTT)
		require.NotZero(t, num0RTT)
		sconn.CloseWithError(0, "")
		require.Len(t, counter.getRcvd0RTTPacketNumbers(), 1)
	})
}
