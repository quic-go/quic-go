package quic

import (
	"crypto/tls"
	"net"
	"slices"
	"testing"
	"time"

	"github.com/quic-go/quic-go/internal/handshake"
	mocklogging "github.com/quic-go/quic-go/internal/mocks/logging"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/qerr"
	"github.com/quic-go/quic-go/internal/wire"
	"github.com/quic-go/quic-go/logging"

	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

func getLongHeaderPacketEncrypted(t *testing.T, remoteAddr net.Addr, extHdr *wire.ExtendedHeader, data []byte) receivedPacket {
	t.Helper()
	hdr := extHdr.Header
	if hdr.Type != protocol.PacketTypeInitial {
		t.Fatal("can only encrypt Initial packets")
	}
	p := getLongHeaderPacket(t, remoteAddr, extHdr, data)
	sealer, _ := handshake.NewInitialAEAD(hdr.DestConnectionID, protocol.PerspectiveClient, hdr.Version)
	n := len(p.data) - len(data) // length of the header
	p.data = slices.Grow(p.data, 16)
	_ = sealer.Seal(p.data[n:n], p.data[n:], extHdr.PacketNumber, p.data[:n])
	p.data = p.data[:len(p.data)+16]
	sealer.EncryptHeader(p.data[n:n+16], &p.data[0], p.data[n-int(extHdr.PacketNumberLen):n])
	return p
}

func TestListen(t *testing.T) {
	_, err := ListenAddr("localhost:0", nil, nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "quic: tls.Config not set")

	_, err = Listen(nil, &tls.Config{}, &Config{Versions: []protocol.Version{0x1234}})
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid QUIC version: 0x1234")
}

func TestListenAddr(t *testing.T) {
	_, err := ListenAddr("127.0.0.1", &tls.Config{}, &Config{})
	require.Error(t, err)
	require.IsType(t, &net.AddrError{}, err)

	_, err = ListenAddr("1.1.1.1:1111", &tls.Config{}, &Config{})
	require.Error(t, err)
	require.IsType(t, &net.OpError{}, err)

	ln, err := ListenAddr("127.0.0.1:0", &tls.Config{}, &Config{})
	require.NoError(t, err)
	defer ln.Close()
}

func TestServerPacketDropping(t *testing.T) {
	t.Run("destination connection ID too short", func(t *testing.T) {
		conn := newUDPConnLocalhost(t)
		testServerDroppedPacket(t,
			conn,
			getLongHeaderPacket(t,
				conn.LocalAddr(),
				&wire.ExtendedHeader{
					Header: wire.Header{
						Type:             protocol.PacketTypeInitial,
						DestConnectionID: protocol.ParseConnectionID([]byte{1, 2, 3, 4}),
						Version:          protocol.Version1,
					},
					PacketNumberLen: 2,
				},
				nil,
			),
			logging.PacketTypeInitial,
			logging.PacketDropUnexpectedPacket,
		)
	})

	t.Run("Initial packet too small", func(t *testing.T) {
		conn := newUDPConnLocalhost(t)
		p := getLongHeaderPacket(t,
			conn.LocalAddr(),
			&wire.ExtendedHeader{
				Header: wire.Header{
					Type:             protocol.PacketTypeInitial,
					DestConnectionID: protocol.ParseConnectionID([]byte{1, 2, 3, 4, 5, 6, 7, 8}),
					Version:          protocol.Version1,
				},
				PacketNumberLen: 2,
			},
			make([]byte, protocol.MinInitialPacketSize-100),
		)
		require.Greater(t, len(p.data), protocol.MinInitialPacketSize-100)
		require.Less(t, len(p.data), protocol.MinInitialPacketSize)
		testServerDroppedPacket(t,
			conn,
			p,
			logging.PacketTypeInitial,
			logging.PacketDropUnexpectedPacket,
		)
	})

	// we should not send a Version Negotiation packet if the packet is smaller than 1200 bytes
	t.Run("packet of unknown versiontoo small", func(t *testing.T) {
		conn := newUDPConnLocalhost(t)
		p := getLongHeaderPacket(t,
			conn.LocalAddr(),
			&wire.ExtendedHeader{
				Header: wire.Header{
					Type:             protocol.PacketTypeInitial,
					DestConnectionID: protocol.ParseConnectionID([]byte{1, 2, 3, 4, 5, 6, 7, 8}),
					Version:          0x42,
				},
				PacketNumberLen: 2,
			},
			make([]byte, protocol.MinUnknownVersionPacketSize-100),
		)
		require.Greater(t, len(p.data), protocol.MinUnknownVersionPacketSize-100)
		require.Less(t, len(p.data), protocol.MinUnknownVersionPacketSize)
		testServerDroppedPacket(t,
			conn,
			p,
			logging.PacketTypeNotDetermined,
			logging.PacketDropUnexpectedPacket,
		)
	})

	t.Run("not an Initial packet", func(t *testing.T) {
		conn := newUDPConnLocalhost(t)
		testServerDroppedPacket(t,
			conn,
			getLongHeaderPacket(t,
				conn.LocalAddr(),
				&wire.ExtendedHeader{
					Header: wire.Header{
						Type:             protocol.PacketTypeHandshake,
						DestConnectionID: protocol.ParseConnectionID([]byte{1, 2, 3, 4, 5, 6, 7, 8}),
						Version:          protocol.Version1,
					},
					PacketNumberLen: 2,
				},
				nil,
			),
			logging.PacketTypeHandshake,
			logging.PacketDropUnexpectedPacket,
		)
	})

	// as a server, we should never receive a Version Negotiation packet
	t.Run("Version Negotiation packet", func(t *testing.T) {
		conn := newUDPConnLocalhost(t)
		data := wire.ComposeVersionNegotiation(
			protocol.ArbitraryLenConnectionID{1, 2, 3, 4},
			protocol.ArbitraryLenConnectionID{4, 3, 2, 1},
			[]protocol.Version{1, 2, 3},
		)
		testServerDroppedPacket(t,
			conn,
			receivedPacket{
				remoteAddr: conn.LocalAddr(),
				data:       data,
				buffer:     getPacketBuffer(),
			},
			logging.PacketTypeVersionNegotiation,
			logging.PacketDropUnexpectedPacket,
		)
	})
}

func testServerDroppedPacket(t *testing.T,
	conn *net.UDPConn,
	p receivedPacket,
	expectedPacketType logging.PacketType,
	expectedDropReason logging.PacketDropReason,
) {
	readChan := make(chan struct{})
	go func() {
		defer close(readChan)
		conn.ReadFrom(make([]byte, 1000))
	}()
	mockCtrl := gomock.NewController(t)
	tracer, mockTracer := mocklogging.NewMockTracer(mockCtrl)
	tr := &Transport{
		Conn:   newUDPConnLocalhost(t),
		Tracer: tracer,
	}
	defer tr.Close()
	ln, err := tr.Listen(&tls.Config{}, nil)
	require.NoError(t, err)
	defer ln.Close()

	mockTracer.EXPECT().DroppedPacket(p.remoteAddr, expectedPacketType, p.Size(), expectedDropReason)
	tr.server.handlePacket(p)

	select {
	case <-readChan:
		t.Fatal("didn't expect to receive a packet")
	case <-time.After(scaleDuration(5 * time.Millisecond)):
	}
	mockTracer.EXPECT().Close()
}

func TestServerVersionNegotiation(t *testing.T) {
	t.Run("enabled", func(t *testing.T) {
		testServerVersionNegotiation(t, true)
	})
	t.Run("disabled", func(t *testing.T) {
		testServerVersionNegotiation(t, false)
	})
}

func testServerVersionNegotiation(t *testing.T, enabled bool) {
	mockCtrl := gomock.NewController(t)
	conn := newUDPConnLocalhost(t)
	tracer, mockTracer := mocklogging.NewMockTracer(mockCtrl)
	tr := &Transport{
		Conn:                             newUDPConnLocalhost(t),
		Tracer:                           tracer,
		DisableVersionNegotiationPackets: !enabled,
	}
	defer tr.Close()
	ln, err := tr.Listen(&tls.Config{}, nil)
	require.NoError(t, err)
	defer ln.Close()

	srcConnID := protocol.ParseConnectionID([]byte{1, 2, 3, 4, 5})
	destConnID := protocol.ParseConnectionID([]byte{1, 2, 3, 4, 5, 6})
	packet := getLongHeaderPacket(t, conn.LocalAddr(),
		&wire.ExtendedHeader{
			Header: wire.Header{
				Type:             protocol.PacketTypeHandshake,
				SrcConnectionID:  srcConnID,
				DestConnectionID: destConnID,
				Version:          0x42,
			},
			PacketNumberLen: protocol.PacketNumberLen4,
		},
		make([]byte, protocol.MinUnknownVersionPacketSize),
	)

	switch enabled {
	case true:
		mockTracer.EXPECT().SentVersionNegotiationPacket(packet.remoteAddr, gomock.Any(), gomock.Any(), gomock.Any())
	case false:
		mockTracer.EXPECT().DroppedPacket(packet.remoteAddr, logging.PacketTypeNotDetermined, packet.Size(), logging.PacketDropUnexpectedVersion)
	}

	written := make(chan []byte, 1)
	go func() {
		b := make([]byte, 1500)
		n, _, _ := conn.ReadFrom(b)
		written <- b[:n]
	}()

	tr.server.handlePacket(packet)

	switch enabled {
	case true:
		select {
		case b := <-written:
			require.True(t, wire.IsVersionNegotiationPacket(b))
			dest, src, versions, err := wire.ParseVersionNegotiationPacket(b)
			require.NoError(t, err)
			require.Equal(t, protocol.ArbitraryLenConnectionID(srcConnID.Bytes()), dest)
			require.Equal(t, protocol.ArbitraryLenConnectionID(destConnID.Bytes()), src)
			require.NotContains(t, versions, protocol.Version(0x42))
		case <-time.After(time.Second):
			t.Fatal("timeout")
		}
	case false:
		select {
		case <-written:
			t.Fatal("expected no version negotiation packet")
		case <-time.After(scaleDuration(10 * time.Millisecond)):
		}
	}
	mockTracer.EXPECT().Close()
}

func TestServerTokenValidation(t *testing.T) {
	tokenGeneratorKey := TokenGeneratorKey{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11}
	tg := handshake.NewTokenGenerator(tokenGeneratorKey)

	t.Run("retry token with invalid address", func(t *testing.T) {
		token, err := tg.NewRetryToken(
			&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1337},
			protocol.ConnectionID{},
			protocol.ConnectionID{},
		)
		require.NoError(t, err)
		tr := &Transport{
			Conn:                newUDPConnLocalhost(t),
			VerifySourceAddress: func(addr net.Addr) bool { return true },
			TokenGeneratorKey:   &tokenGeneratorKey,
		}
		defer tr.Close()

		testServerTokenValidation(t, tr, 10*time.Second, newUDPConnLocalhost(t), token)
	})

	t.Run("expired retry token", func(t *testing.T) {
		conn := newUDPConnLocalhost(t)
		token, err := tg.NewRetryToken(conn.LocalAddr(), protocol.ConnectionID{}, protocol.ConnectionID{})
		require.NoError(t, err)
		tr := &Transport{
			Conn:                newUDPConnLocalhost(t),
			VerifySourceAddress: func(addr net.Addr) bool { return true },
			TokenGeneratorKey:   &tokenGeneratorKey,
		}
		defer tr.Close()

		// the maximum retry token age is equivalent to the handshake timeout
		handshakeIdleTimeout := time.Millisecond / 2
		time.Sleep(time.Millisecond) // make sure the token is expired
		testServerTokenValidation(t, tr, handshakeIdleTimeout, conn, token)
	})
}

func testServerTokenValidation(
	t *testing.T,
	tr *Transport,
	handshakeIdleTimeout time.Duration,
	conn *net.UDPConn,
	token []byte,
) {
	mockCtrl := gomock.NewController(t)
	tracer, mockTracer := mocklogging.NewMockTracer(mockCtrl)
	mockTracer.EXPECT().Close()
	tr.Tracer = tracer

	ln, err := tr.Listen(&tls.Config{}, &Config{HandshakeIdleTimeout: handshakeIdleTimeout})
	require.NoError(t, err)
	defer ln.Close()

	hdr := wire.Header{
		Type:             protocol.PacketTypeInitial,
		SrcConnectionID:  protocol.ParseConnectionID([]byte{5, 4, 3, 2, 1}),
		DestConnectionID: protocol.ParseConnectionID([]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}),
		Token:            token,
		Length:           protocol.MinInitialPacketSize + protocol.ByteCount(protocol.PacketNumberLen4) + 16,
		Version:          protocol.Version1,
	}
	packet := getLongHeaderPacketEncrypted(t,
		conn.LocalAddr(),
		&wire.ExtendedHeader{Header: hdr, PacketNumberLen: protocol.PacketNumberLen4},
		make([]byte, protocol.MinInitialPacketSize),
	)

	replyHdrChan := make(chan *logging.Header, 1)
	var replyFrames []logging.Frame
	mockTracer.EXPECT().SentPacket(packet.remoteAddr, gomock.Any(), gomock.Any(), gomock.Any()).Do(func(_ net.Addr, hdr *logging.Header, _ logging.ByteCount, frames []logging.Frame) {
		replyFrames = frames
		replyHdrChan <- hdr
	})

	tr.server.handlePacket(packet)
	conn.SetReadDeadline(time.Now().Add(time.Second))
	_, _, err = conn.ReadFromUDP(make([]byte, 1000))
	require.NoError(t, err)
	replyHdr := <-replyHdrChan
	require.Equal(t, protocol.PacketTypeInitial, replyHdr.Type)
	require.Equal(t, hdr.DestConnectionID, replyHdr.SrcConnectionID)
	require.Equal(t, hdr.SrcConnectionID, replyHdr.DestConnectionID)
	require.Len(t, replyFrames, 1)
	require.IsType(t, &wire.ConnectionCloseFrame{}, replyFrames[0])
	ccf := replyFrames[0].(*logging.ConnectionCloseFrame)
	require.False(t, ccf.IsApplicationError)
	require.EqualValues(t, qerr.InvalidToken, ccf.ErrorCode)
}
