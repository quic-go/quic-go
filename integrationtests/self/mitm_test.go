package self_test

import (
	"context"
	"errors"
	"io"
	"math"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/exp/rand"

	"github.com/quic-go/quic-go"
	quicproxy "github.com/quic-go/quic-go/integrationtests/tools/proxy"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/wire"
	"github.com/quic-go/quic-go/testutils"

	"github.com/stretchr/testify/require"
)

const mitmTestConnIDLen = 6

func getTransportsForMITMTest(t *testing.T) (serverTransport, clientTransport *quic.Transport) {
	serverTransport = &quic.Transport{
		Conn:               newUPDConnLocalhost(t),
		ConnectionIDLength: mitmTestConnIDLen,
	}
	addTracer(serverTransport)
	t.Cleanup(func() { serverTransport.Close() })

	clientTransport = &quic.Transport{
		Conn:               newUPDConnLocalhost(t),
		ConnectionIDLength: mitmTestConnIDLen,
	}
	addTracer(clientTransport)
	t.Cleanup(func() { clientTransport.Close() })

	return serverTransport, clientTransport
}

func TestMITMInjectRandomPackets(t *testing.T) {
	t.Run("towards the server", func(t *testing.T) {
		testMITMInjectRandomPackets(t, quicproxy.DirectionIncoming)
	})

	t.Run("towards the client", func(t *testing.T) {
		testMITMInjectRandomPackets(t, quicproxy.DirectionOutgoing)
	})
}

func TestMITMDuplicatePackets(t *testing.T) {
	t.Run("towards the server", func(t *testing.T) {
		testMITMDuplicatePackets(t, quicproxy.DirectionIncoming)
	})

	t.Run("towards the client", func(t *testing.T) {
		testMITMDuplicatePackets(t, quicproxy.DirectionOutgoing)
	})
}

func TestMITCorruptPackets(t *testing.T) {
	t.Run("towards the server", func(t *testing.T) {
		testMITMCorruptPackets(t, quicproxy.DirectionIncoming)
	})

	t.Run("towards the client", func(t *testing.T) {
		testMITMCorruptPackets(t, quicproxy.DirectionOutgoing)
	})
}

func testMITMInjectRandomPackets(t *testing.T, direction quicproxy.Direction) {
	createRandomPacketOfSameType := func(b []byte) []byte {
		if wire.IsLongHeaderPacket(b[0]) {
			hdr, _, _, err := wire.ParsePacket(b)
			if err != nil {
				return nil
			}
			replyHdr := &wire.ExtendedHeader{
				Header: wire.Header{
					DestConnectionID: hdr.DestConnectionID,
					SrcConnectionID:  hdr.SrcConnectionID,
					Type:             hdr.Type,
					Version:          hdr.Version,
				},
				PacketNumber:    protocol.PacketNumber(rand.Int31n(math.MaxInt32 / 4)),
				PacketNumberLen: protocol.PacketNumberLen(rand.Int31n(4) + 1),
			}
			payloadLen := rand.Int31n(100)
			replyHdr.Length = protocol.ByteCount(rand.Int31n(payloadLen + 1))
			data, err := replyHdr.Append(nil, hdr.Version)
			if err != nil {
				panic("failed to append header: " + err.Error())
			}
			r := make([]byte, payloadLen)
			rand.Read(r)
			return append(data, r...)
		}
		// short header packet
		connID, err := wire.ParseConnectionID(b, mitmTestConnIDLen)
		if err != nil {
			return nil
		}
		_, pn, pnLen, _, err := wire.ParseShortHeader(b, mitmTestConnIDLen)
		if err != nil && !errors.Is(err, wire.ErrInvalidReservedBits) { // normally, ParseShortHeader is called after decrypting the header
			panic("failed to parse short header: " + err.Error())
		}
		data, err := wire.AppendShortHeader(nil, connID, pn, pnLen, protocol.KeyPhaseBit(rand.Intn(2)))
		if err != nil {
			return nil
		}
		payloadLen := rand.Int31n(100)
		r := make([]byte, payloadLen)
		rand.Read(r)
		return append(data, r...)
	}

	rtt := scaleDuration(10 * time.Millisecond)
	serverTransport, clientTransport := getTransportsForMITMTest(t)

	dropCallback := func(dir quicproxy.Direction, b []byte) bool {
		if dir != direction {
			return false
		}
		go func() {
			ticker := time.NewTicker(rtt / 10)
			defer ticker.Stop()
			for i := 0; i < 10; i++ {
				switch direction {
				case quicproxy.DirectionIncoming:
					clientTransport.WriteTo(createRandomPacketOfSameType(b), serverTransport.Conn.LocalAddr())
				case quicproxy.DirectionOutgoing:
					serverTransport.WriteTo(createRandomPacketOfSameType(b), clientTransport.Conn.LocalAddr())
				}
				<-ticker.C
			}
		}()
		return false
	}

	runMITMTest(t, serverTransport, clientTransport, rtt, dropCallback)
}

func testMITMDuplicatePackets(t *testing.T, direction quicproxy.Direction) {
	serverTransport, clientTransport := getTransportsForMITMTest(t)
	rtt := scaleDuration(10 * time.Millisecond)

	dropCallback := func(dir quicproxy.Direction, b []byte) bool {
		if dir != direction {
			return false
		}
		switch direction {
		case quicproxy.DirectionIncoming:
			clientTransport.WriteTo(b, serverTransport.Conn.LocalAddr())
		case quicproxy.DirectionOutgoing:
			serverTransport.WriteTo(b, clientTransport.Conn.LocalAddr())
		}
		return false
	}

	runMITMTest(t, serverTransport, clientTransport, rtt, dropCallback)
}

func testMITMCorruptPackets(t *testing.T, direction quicproxy.Direction) {
	serverTransport, clientTransport := getTransportsForMITMTest(t)
	rtt := scaleDuration(5 * time.Millisecond)

	var numCorrupted atomic.Int32
	dropCallback := func(dir quicproxy.Direction, b []byte) bool {
		if dir != direction {
			return false
		}
		isLongHeaderPacket := wire.IsLongHeaderPacket(b[0])
		// corrupt 20% of long header packets and 5% of short header packets
		if isLongHeaderPacket && rand.Intn(4) != 0 {
			return false
		}
		if !isLongHeaderPacket && rand.Intn(20) != 0 {
			return false
		}
		numCorrupted.Add(1)
		pos := rand.Intn(len(b))
		b[pos] = byte(rand.Intn(256))
		switch direction {
		case quicproxy.DirectionIncoming:
			clientTransport.WriteTo(b, serverTransport.Conn.LocalAddr())
		case quicproxy.DirectionOutgoing:
			serverTransport.WriteTo(b, clientTransport.Conn.LocalAddr())
		}
		return true
	}

	runMITMTest(t, serverTransport, clientTransport, rtt, dropCallback)
	t.Logf("corrupted %d packets", numCorrupted.Load())
	require.NotZero(t, int(numCorrupted.Load()))
}

func runMITMTest(t *testing.T, serverTr, clientTr *quic.Transport, rtt time.Duration, dropCb quicproxy.DropCallback) {
	ln, err := serverTr.Listen(getTLSConfig(), getQuicConfig(nil))
	require.NoError(t, err)
	defer ln.Close()

	proxy := quicproxy.Proxy{
		Conn:        newUPDConnLocalhost(t),
		ServerAddr:  ln.Addr().(*net.UDPAddr),
		DelayPacket: func(_ quicproxy.Direction, b []byte) time.Duration { return rtt / 2 },
		DropPacket:  dropCb,
	}
	require.NoError(t, proxy.Start())
	defer proxy.Close()

	ctx, cancel := context.WithTimeout(context.Background(), scaleDuration(time.Second))
	defer cancel()
	conn, err := clientTr.Dial(ctx, proxy.LocalAddr(), getTLSClientConfig(), getQuicConfig(nil))
	require.NoError(t, err)
	defer conn.CloseWithError(0, "")

	serverConn, err := ln.Accept(ctx)
	require.NoError(t, err)
	defer serverConn.CloseWithError(0, "")

	str, err := conn.OpenStreamSync(ctx)
	require.NoError(t, err)
	clientErrChan := make(chan error, 1)
	go func() {
		_, err := str.Write(PRData)
		clientErrChan <- err
		str.Close()
	}()

	serverStr, err := serverConn.AcceptStream(ctx)
	require.NoError(t, err)
	serverErrChan := make(chan error, 1)
	go func() {
		defer close(serverErrChan)
		if _, err := io.Copy(serverStr, serverStr); err != nil {
			serverErrChan <- err
			return
		}
		serverStr.Close()
	}()
	require.NoError(t, <-serverErrChan)

	data, err := io.ReadAll(str)
	require.NoError(t, err)
	require.Equal(t, PRData, data)

	select {
	case err := <-clientErrChan:
		require.NoError(t, err)
	case <-time.After(time.Second):
		t.Fatal("timeout")
	}
	select {
	case err := <-serverErrChan:
		require.NoError(t, err)
	case <-time.After(time.Second):
		t.Fatal("timeout")
	}
}

func TestMITMForgedVersionNegotiationPacket(t *testing.T) {
	serverTransport, clientTransport := getTransportsForMITMTest(t)
	rtt := scaleDuration(10 * time.Millisecond)

	const supportedVersion protocol.Version = 42

	var once sync.Once
	delayCb := func(dir quicproxy.Direction, raw []byte) time.Duration {
		if dir != quicproxy.DirectionIncoming {
			return rtt / 2
		}
		once.Do(func() {
			hdr, _, _, err := wire.ParsePacket(raw)
			if err != nil {
				panic("failed to parse packet: " + err.Error())
			}
			// create fake version negotiation packet with a fake supported version
			packet := wire.ComposeVersionNegotiation(
				protocol.ArbitraryLenConnectionID(hdr.SrcConnectionID.Bytes()),
				protocol.ArbitraryLenConnectionID(hdr.DestConnectionID.Bytes()),
				[]protocol.Version{supportedVersion},
			)
			if _, err := serverTransport.WriteTo(packet, clientTransport.Conn.LocalAddr()); err != nil {
				panic("failed to write packet: " + err.Error())
			}
		})
		return rtt / 2
	}

	err := runMITMTestSuccessful(t, serverTransport, clientTransport, delayCb)
	var vnErr *quic.VersionNegotiationError
	require.ErrorAs(t, err, &vnErr)
	require.Contains(t, vnErr.Theirs, supportedVersion) // might contain greased versions
}

// times out, because client doesn't accept subsequent real retry packets from server
// as it has already accepted a retry.
// TODO: determine behavior when server does not send Retry packets
func TestMITMForgedRetryPacket(t *testing.T) {
	serverTransport, clientTransport := getTransportsForMITMTest(t)
	serverTransport.VerifySourceAddress = func(net.Addr) bool { return true }
	rtt := scaleDuration(10 * time.Millisecond)

	var once sync.Once
	delayCb := func(dir quicproxy.Direction, raw []byte) time.Duration {
		hdr, _, _, err := wire.ParsePacket(raw)
		if err != nil {
			panic("failed to parse packet: " + err.Error())
		}
		if dir == quicproxy.DirectionIncoming && hdr.Type == protocol.PacketTypeInitial {
			once.Do(func() {
				fakeSrcConnID := protocol.ParseConnectionID([]byte{0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12})
				retryPacket := testutils.ComposeRetryPacket(fakeSrcConnID, hdr.SrcConnectionID, hdr.DestConnectionID, []byte("token"), hdr.Version)
				if _, err := serverTransport.WriteTo(retryPacket, clientTransport.Conn.LocalAddr()); err != nil {
					panic("failed to write packet: " + err.Error())
				}
			})
		}
		return rtt / 2
	}
	err := runMITMTestSuccessful(t, serverTransport, clientTransport, delayCb)
	var nerr net.Error
	require.ErrorAs(t, err, &nerr)
	require.True(t, nerr.Timeout())
}

func TestMITMForgedInitialPacket(t *testing.T) {
	serverTransport, clientTransport := getTransportsForMITMTest(t)
	rtt := scaleDuration(10 * time.Millisecond)

	var once sync.Once
	delayCb := func(dir quicproxy.Direction, raw []byte) time.Duration {
		if dir == quicproxy.DirectionIncoming {
			hdr, _, _, err := wire.ParsePacket(raw)
			if err != nil {
				panic("failed to parse packet: " + err.Error())
			}
			if hdr.Type != protocol.PacketTypeInitial {
				return 0
			}
			once.Do(func() {
				initialPacket := testutils.ComposeInitialPacket(
					hdr.DestConnectionID,
					hdr.SrcConnectionID,
					hdr.DestConnectionID,
					nil,
					nil,
					protocol.PerspectiveServer,
					hdr.Version,
				)
				if _, err := serverTransport.WriteTo(initialPacket, clientTransport.Conn.LocalAddr()); err != nil {
					panic("failed to write packet: " + err.Error())
				}
			})
		}
		return rtt / 2
	}
	err := runMITMTestSuccessful(t, serverTransport, clientTransport, delayCb)
	var nerr net.Error
	require.ErrorAs(t, err, &nerr)
	require.True(t, nerr.Timeout())
}

func TestMITMForgedInitialPacketWithAck(t *testing.T) {
	serverTransport, clientTransport := getTransportsForMITMTest(t)
	rtt := scaleDuration(10 * time.Millisecond)

	var once sync.Once
	delayCb := func(dir quicproxy.Direction, raw []byte) time.Duration {
		if dir == quicproxy.DirectionIncoming {
			hdr, _, _, err := wire.ParsePacket(raw)
			if err != nil {
				panic("failed to parse packet: " + err.Error())
			}
			if hdr.Type != protocol.PacketTypeInitial {
				return 0
			}
			once.Do(func() {
				// Fake Initial with ACK for packet 2 (unsent)
				ack := &wire.AckFrame{AckRanges: []wire.AckRange{{Smallest: 2, Largest: 2}}}
				initialPacket := testutils.ComposeInitialPacket(
					hdr.DestConnectionID,
					hdr.SrcConnectionID,
					hdr.DestConnectionID,
					nil,
					[]wire.Frame{ack},
					protocol.PerspectiveServer,
					hdr.Version,
				)
				if _, err := serverTransport.WriteTo(initialPacket, clientTransport.Conn.LocalAddr()); err != nil {
					panic("failed to write packet: " + err.Error())
				}
			})
		}
		return rtt / 2
	}

	err := runMITMTestSuccessful(t, serverTransport, clientTransport, delayCb)
	var transportErr *quic.TransportError
	require.ErrorAs(t, err, &transportErr)
	require.Equal(t, quic.ProtocolViolation, transportErr.ErrorCode)
	require.Contains(t, transportErr.ErrorMessage, "received ACK for an unsent packet")
}

func runMITMTestSuccessful(t *testing.T, serverTransport, clientTransport *quic.Transport, delayCb quicproxy.DelayCallback) error {
	t.Helper()
	ln, err := serverTransport.Listen(getTLSConfig(), getQuicConfig(nil))
	require.NoError(t, err)
	defer ln.Close()

	proxy := quicproxy.Proxy{
		Conn:        newUPDConnLocalhost(t),
		ServerAddr:  ln.Addr().(*net.UDPAddr),
		DelayPacket: delayCb,
	}
	require.NoError(t, proxy.Start())
	defer proxy.Close()

	ctx, cancel := context.WithTimeout(context.Background(), scaleDuration(50*time.Millisecond))
	defer cancel()
	_, err = clientTransport.Dial(ctx, proxy.LocalAddr(), getTLSClientConfig(), getQuicConfig(nil))
	require.Error(t, err)
	return err
}
