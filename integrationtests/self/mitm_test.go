package self_test

import (
	"context"
	"crypto/rand"
	"errors"
	"io"
	"math"
	mrand "math/rand/v2"
	"net"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/wire"
	"github.com/quic-go/quic-go/testutils"
	"github.com/quic-go/quic-go/testutils/simnet"

	"github.com/stretchr/testify/require"
)

const (
	mitmTestConnIDLen = 6
	mitmTestRTT       = 10 * time.Millisecond
)

// mitmPacket is a packet that is delivered after Delay, in addition to the link latency.
type mitmPacket struct {
	simnet.Packet
	Delay time.Duration
}

// mitmRouter delivers the packets returned by Intercept instead of the packet that was sent.
type mitmRouter struct {
	simnet.PerfectRouter

	ServerAddr net.Addr
	Intercept  func(dir direction, p simnet.Packet) []mitmPacket
}

var _ simnet.Router = &mitmRouter{}

func (r *mitmRouter) SendPacket(p simnet.Packet) error {
	dir := direction(directionToClient)
	if p.To.String() == r.ServerAddr.String() {
		dir = directionToServer
	}
	for _, mp := range r.Intercept(dir, p) {
		if mp.Delay > 0 {
			time.AfterFunc(mp.Delay, func() { r.PerfectRouter.SendPacket(mp.Packet) })
			continue
		}
		if err := r.PerfectRouter.SendPacket(mp.Packet); err != nil {
			return err
		}
	}
	return nil
}

func getTransportsForMITMTest(
	t *testing.T,
	intercept func(dir direction, p simnet.Packet) []mitmPacket,
) (serverTransport, clientTransport *quic.Transport) {
	clientConn, serverConn, closeFn := newSimnetLinkWithRouter(t, mitmTestRTT, &mitmRouter{
		ServerAddr: &net.UDPAddr{IP: net.ParseIP("1.0.0.2"), Port: 9002},
		Intercept:  intercept,
	})
	t.Cleanup(func() { closeFn(t) })

	serverTransport = &quic.Transport{
		Conn:               serverConn,
		ConnectionIDLength: mitmTestConnIDLen,
	}
	addTracer(serverTransport)
	t.Cleanup(func() { serverTransport.Close() })

	clientTransport = &quic.Transport{
		Conn:               clientConn,
		ConnectionIDLength: mitmTestConnIDLen,
	}
	addTracer(clientTransport)
	t.Cleanup(func() { clientTransport.Close() })

	return serverTransport, clientTransport
}

func TestMITMInjectRandomPackets(t *testing.T) {
	t.Run("towards the server", func(t *testing.T) {
		testMITMInjectRandomPackets(t, directionToServer)
	})

	t.Run("towards the client", func(t *testing.T) {
		testMITMInjectRandomPackets(t, directionToClient)
	})
}

func TestMITMDuplicatePackets(t *testing.T) {
	t.Run("towards the server", func(t *testing.T) {
		testMITMDuplicatePackets(t, directionToServer)
	})

	t.Run("towards the client", func(t *testing.T) {
		testMITMDuplicatePackets(t, directionToClient)
	})
}

func TestMITCorruptPackets(t *testing.T) {
	t.Run("towards the server", func(t *testing.T) {
		testMITMCorruptPackets(t, directionToServer)
	})

	t.Run("towards the client", func(t *testing.T) {
		testMITMCorruptPackets(t, directionToClient)
	})
}

func testMITMInjectRandomPackets(t *testing.T, dir direction) {
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
				PacketNumber:    protocol.PacketNumber(mrand.Int32N(math.MaxInt32 / 4)),
				PacketNumberLen: protocol.PacketNumberLen(mrand.IntN(4) + 1),
			}
			payloadLen := mrand.IntN(100)
			replyHdr.Length = protocol.ByteCount(mrand.IntN(payloadLen + 1))
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
		data, err := wire.AppendShortHeader(nil, connID, pn, pnLen, protocol.KeyPhaseBit(mrand.IntN(2)))
		if err != nil {
			return nil
		}
		payloadLen := mrand.IntN(100)
		r := make([]byte, payloadLen)
		rand.Read(r)
		return append(data, r...)
	}

	synctest.Test(t, func(t *testing.T) {
		serverTransport, clientTransport := getTransportsForMITMTest(t, func(d direction, p simnet.Packet) []mitmPacket {
			packets := []mitmPacket{{Packet: p}}
			if d != dir {
				return packets
			}
			for range 10 {
				packets = append(packets, mitmPacket{
					Packet: simnet.Packet{From: p.From, To: p.To, Data: createRandomPacketOfSameType(p.Data)},
					Delay:  mrand.N(mitmTestRTT),
				})
			}
			return packets
		})
		runMITMTest(t, serverTransport, clientTransport)
	})
}

func testMITMDuplicatePackets(t *testing.T, dir direction) {
	synctest.Test(t, func(t *testing.T) {
		serverTransport, clientTransport := getTransportsForMITMTest(t, func(d direction, p simnet.Packet) []mitmPacket {
			if d != dir {
				return []mitmPacket{{Packet: p}}
			}
			return []mitmPacket{
				{Packet: p},
				{Packet: simnet.Packet{From: p.From, To: p.To, Data: slices.Clone(p.Data)}, Delay: mrand.N(mitmTestRTT)},
			}
		})
		runMITMTest(t, serverTransport, clientTransport)
	})
}

func testMITMCorruptPackets(t *testing.T, dir direction) {
	synctest.Test(t, func(t *testing.T) {
		var numCorrupted atomic.Int32
		serverTransport, clientTransport := getTransportsForMITMTest(t, func(d direction, p simnet.Packet) []mitmPacket {
			if d != dir {
				return []mitmPacket{{Packet: p}}
			}
			isLongHeaderPacket := wire.IsLongHeaderPacket(p.Data[0])
			// corrupt 20% of long header packets and 5% of short header packets
			if isLongHeaderPacket && mrand.IntN(4) != 0 {
				return []mitmPacket{{Packet: p}}
			}
			if !isLongHeaderPacket && mrand.IntN(20) != 0 {
				return []mitmPacket{{Packet: p}}
			}
			numCorrupted.Add(1)
			p.Data = slices.Clone(p.Data)
			p.Data[mrand.IntN(len(p.Data))] = byte(mrand.IntN(256))
			return []mitmPacket{{Packet: p}}
		})

		runMITMTest(t, serverTransport, clientTransport)
		t.Logf("corrupted %d packets", numCorrupted.Load())
		require.NotZero(t, int(numCorrupted.Load()))
	})
}

func runMITMTest(t *testing.T, serverTr, clientTr *quic.Transport) {
	ln, err := serverTr.Listen(getTLSConfig(), getQuicConfig(nil))
	require.NoError(t, err)
	defer ln.Close()

	// corrupted handshake packets can lead to multiple PTOs with exponential backoff
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := clientTr.Dial(ctx, ln.Addr(), getTLSClientConfig(), getQuicConfig(nil))
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
	synctest.Test(t, func(t *testing.T) {
		const supportedVersion protocol.Version = 42

		var once sync.Once
		serverTransport, clientTransport := getTransportsForMITMTest(t, func(d direction, p simnet.Packet) []mitmPacket {
			packets := []mitmPacket{{Packet: p}}
			if d != directionToServer {
				return packets
			}
			once.Do(func() {
				hdr, _, _, err := wire.ParsePacket(p.Data)
				if err != nil {
					panic("failed to parse packet: " + err.Error())
				}
				// create fake version negotiation packet with a fake supported version
				packet := wire.ComposeVersionNegotiation(
					protocol.ArbitraryLenConnectionID(hdr.SrcConnectionID.Bytes()),
					protocol.ArbitraryLenConnectionID(hdr.DestConnectionID.Bytes()),
					[]protocol.Version{supportedVersion},
				)
				packets = append(packets, mitmPacket{Packet: simnet.Packet{From: p.To, To: p.From, Data: packet}})
			})
			return packets
		})

		err := runMITMTestSuccessful(t, serverTransport, clientTransport)
		var vnErr *quic.VersionNegotiationError
		require.ErrorAs(t, err, &vnErr)
		require.Contains(t, vnErr.Theirs, supportedVersion) // might contain greased versions
	})
}

// times out, because client doesn't accept subsequent real retry packets from server
// as it has already accepted a retry.
// TODO: determine behavior when server does not send Retry packets
func TestMITMForgedRetryPacket(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var once sync.Once
		serverTransport, clientTransport := getTransportsForMITMTest(t, func(d direction, p simnet.Packet) []mitmPacket {
			packets := []mitmPacket{{Packet: p}}
			hdr, _, _, err := wire.ParsePacket(p.Data)
			if err != nil {
				panic("failed to parse packet: " + err.Error())
			}
			if d == directionToServer && hdr.Type == protocol.PacketTypeInitial {
				once.Do(func() {
					fakeSrcConnID := protocol.ParseConnectionID([]byte{0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12})
					retryPacket := testutils.ComposeRetryPacket(fakeSrcConnID, hdr.SrcConnectionID, hdr.DestConnectionID, []byte("token"), hdr.Version)
					packets = append(packets, mitmPacket{Packet: simnet.Packet{From: p.To, To: p.From, Data: retryPacket}})
				})
			}
			return packets
		})
		serverTransport.VerifySourceAddress = func(net.Addr) bool { return true }

		err := runMITMTestSuccessful(t, serverTransport, clientTransport)
		var nerr net.Error
		require.ErrorAs(t, err, &nerr)
		require.True(t, nerr.Timeout())
	})
}

func TestMITMForgedInitialPacket(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var once sync.Once
		serverTransport, clientTransport := getTransportsForMITMTest(t, func(d direction, p simnet.Packet) []mitmPacket {
			packets := []mitmPacket{{Packet: p}}
			if d != directionToServer {
				return packets
			}
			hdr, _, _, err := wire.ParsePacket(p.Data)
			if err != nil {
				panic("failed to parse packet: " + err.Error())
			}
			if hdr.Type != protocol.PacketTypeInitial {
				return packets
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
				packets = append(packets, mitmPacket{Packet: simnet.Packet{From: p.To, To: p.From, Data: initialPacket}})
			})
			return packets
		})

		err := runMITMTestSuccessful(t, serverTransport, clientTransport)
		var nerr net.Error
		require.ErrorAs(t, err, &nerr)
		require.True(t, nerr.Timeout())
	})
}

func TestMITMForgedInitialPacketWithAck(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var once sync.Once
		serverTransport, clientTransport := getTransportsForMITMTest(t, func(d direction, p simnet.Packet) []mitmPacket {
			packets := []mitmPacket{{Packet: p}}
			if d != directionToServer {
				return packets
			}
			hdr, _, _, err := wire.ParsePacket(p.Data)
			if err != nil {
				panic("failed to parse packet: " + err.Error())
			}
			if hdr.Type != protocol.PacketTypeInitial {
				return packets
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
				packets = append(packets, mitmPacket{Packet: simnet.Packet{From: p.To, To: p.From, Data: initialPacket}})
			})
			return packets
		})

		err := runMITMTestSuccessful(t, serverTransport, clientTransport)
		var transportErr *quic.TransportError
		require.ErrorAs(t, err, &transportErr)
		require.Equal(t, quic.ProtocolViolation, transportErr.ErrorCode)
		require.Contains(t, transportErr.ErrorMessage, "received ACK for an unsent packet")
	})
}

func runMITMTestSuccessful(t *testing.T, serverTransport, clientTransport *quic.Transport) error {
	t.Helper()
	ln, err := serverTransport.Listen(getTLSConfig(), getQuicConfig(nil))
	require.NoError(t, err)
	defer ln.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	_, err = clientTransport.Dial(ctx, ln.Addr(), getTLSClientConfig(), getQuicConfig(nil))
	require.Error(t, err)
	return err
}
