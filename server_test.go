package quic

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"errors"
	"net"
	"slices"
	"testing"
	"time"

	"github.com/quic-go/quic-go/internal/handshake"
	"github.com/quic-go/quic-go/internal/monotime"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/qerr"
	"github.com/quic-go/quic-go/internal/utils"
	"github.com/quic-go/quic-go/internal/wire"
	"github.com/quic-go/quic-go/qlog"
	"github.com/quic-go/quic-go/qlogwriter"
	"github.com/quic-go/quic-go/testutils/events"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type testServer struct{ *baseServer }

type serverOpts struct {
	eventRecorder             *events.Recorder
	config                    *Config
	tokenGeneratorKey         TokenGeneratorKey
	maxTokenAge               time.Duration
	useRetry                  bool
	disableVersionNegotiation bool
	acceptEarly               bool
	newConn                   func(
		context.Context,
		context.CancelCauseFunc,
		sendConn,
		connRunner,
		protocol.ConnectionID, // original dest connection ID
		*protocol.ConnectionID, // retry src connection ID
		protocol.ConnectionID, // client dest connection ID
		protocol.ConnectionID, // destination connection ID
		protocol.ConnectionID, // source connection ID
		ConnectionIDGenerator,
		*statelessResetter,
		*Config,
		*tls.Config,
		*handshake.TokenGenerator,
		bool, /* client address validated by an address validation token */
		time.Duration,
		qlogwriter.Recorder,
		utils.Logger,
		protocol.Version,
	) *wrappedConn
}

func newTestServer(t *testing.T, serverOpts *serverOpts) *testServer {
	t.Helper()
	c, err := wrapConn(newUDPConnLocalhost(t))
	require.NoError(t, err)
	verifySourceAddress := func(net.Addr) bool { return serverOpts.useRetry }
	config := populateConfig(serverOpts.config)
	tr := &Transport{Conn: newUDPConnLocalhost(t)}
	tr.init(true)
	s := newServer(
		c,
		(*packetHandlerMap)(tr),
		&protocol.DefaultConnectionIDGenerator{},
		&statelessResetter{},
		func(ctx context.Context, _ *ClientInfo) (context.Context, error) { return ctx, nil },
		&tls.Config{},
		config,
		serverOpts.eventRecorder,
		func() {},
		serverOpts.tokenGeneratorKey,
		serverOpts.maxTokenAge,
		verifySourceAddress,
		serverOpts.disableVersionNegotiation,
		serverOpts.acceptEarly,
	)
	s.newConn = serverOpts.newConn
	t.Cleanup(func() { s.Close() })
	return &testServer{s}
}

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

func randConnID(l int) protocol.ConnectionID {
	b := make([]byte, l)
	rand.Read(b)
	return protocol.ParseConnectionID(b)
}

func getValidInitialPacket(t *testing.T, raddr net.Addr, srcConnID, destConnID protocol.ConnectionID) receivedPacket {
	t.Helper()
	return getLongHeaderPacket(t,
		raddr,
		&wire.ExtendedHeader{
			Header: wire.Header{
				Type:             protocol.PacketTypeInitial,
				SrcConnectionID:  srcConnID,
				DestConnectionID: destConnID,
				Length:           protocol.MinInitialPacketSize,
				Version:          protocol.Version1,
			},
			PacketNumberLen: protocol.PacketNumberLen4,
		},
		make([]byte, protocol.MinInitialPacketSize),
	)
}

// checkConnectionClose checks
//  1. the arguments of the SentPacket tracer call, and
//  2. reads and parses the packet sent by the server
func checkConnectionClose(
	t *testing.T,
	conn *net.UDPConn,
	eventRecorder *events.Recorder,
	expectedSrcConnID protocol.ConnectionID,
	expectedDestConnID protocol.ConnectionID,
	expectedErrorCode qerr.TransportErrorCode,
) {
	t.Helper()

	conn.SetReadDeadline(time.Now().Add(time.Second))
	b := make([]byte, 1500)
	n, _, err := conn.ReadFromUDP(b)
	require.NoError(t, err)
	parsedHdr, _, _, err := wire.ParsePacket(b[:n])
	require.NoError(t, err)
	require.Equal(t, protocol.PacketTypeInitial, parsedHdr.Type)
	require.Equal(t, expectedSrcConnID, parsedHdr.SrcConnectionID)
	require.Equal(t, expectedDestConnID, parsedHdr.DestConnectionID)

	require.Equal(t,
		[]qlogwriter.Event{
			qlog.PacketSent{
				Header: qlog.PacketHeader{
					PacketType:       qlog.PacketTypeInitial,
					SrcConnectionID:  expectedSrcConnID,
					DestConnectionID: expectedDestConnID,
					Version:          protocol.Version1,
				},
				Raw: qlog.RawInfo{Length: n, PayloadLength: int(parsedHdr.Length)},
				Frames: []qlog.Frame{
					{Frame: &qlog.ConnectionCloseFrame{ErrorCode: uint64(expectedErrorCode)}},
				},
			},
		},
		eventRecorder.Events(qlog.PacketSent{}),
	)
}

func checkRetry(t *testing.T,
	conn *net.UDPConn,
	eventRecorder *events.Recorder,
	expectedDestConnID protocol.ConnectionID,
) {
	t.Helper()

	conn.SetReadDeadline(time.Now().Add(time.Second))
	b := make([]byte, 1500)
	n, _, err := conn.ReadFromUDP(b)
	require.NoError(t, err)
	parsedHdr, _, _, err := wire.ParsePacket(b[:n])
	require.NoError(t, err)
	require.Equal(t, protocol.PacketTypeRetry, parsedHdr.Type)
	require.Equal(t, expectedDestConnID, parsedHdr.DestConnectionID)
	require.NotNil(t, parsedHdr.Token)

	require.Equal(t,
		[]qlogwriter.Event{
			qlog.PacketSent{
				Header: qlog.PacketHeader{
					PacketType:       qlog.PacketTypeRetry,
					DestConnectionID: expectedDestConnID,
					SrcConnectionID:  parsedHdr.SrcConnectionID,
					Version:          parsedHdr.Version,
					Token:            &qlog.Token{Raw: parsedHdr.Token},
				},
				Raw: qlog.RawInfo{Length: n},
			},
		},
		eventRecorder.Events(qlog.PacketSent{}),
	)
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
			getValidInitialPacket(t, conn.LocalAddr(), randConnID(5), randConnID(7)),
			protocol.Version1,
			qlog.PacketTypeInitial,
			qlog.PacketDropUnexpectedPacket,
		)
	})

	t.Run("Initial packet too small", func(t *testing.T) {
		conn := newUDPConnLocalhost(t)
		p := getLongHeaderPacket(t,
			conn.LocalAddr(),
			&wire.ExtendedHeader{
				Header: wire.Header{
					Type:             protocol.PacketTypeInitial,
					DestConnectionID: randConnID(8),
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
			protocol.Version1,
			qlog.PacketTypeInitial,
			qlog.PacketDropUnexpectedPacket,
		)
	})

	// we should not send a Version Negotiation packet if the packet is smaller than 1200 bytes
	t.Run("packet of unknown version, too small", func(t *testing.T) {
		conn := newUDPConnLocalhost(t)
		p := getLongHeaderPacket(t,
			conn.LocalAddr(),
			&wire.ExtendedHeader{
				Header: wire.Header{
					Type:             protocol.PacketTypeInitial,
					DestConnectionID: randConnID(8),
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
			0x42,
			"",
			qlog.PacketDropUnexpectedPacket,
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
			protocol.Version1,
			qlog.PacketTypeHandshake,
			qlog.PacketDropUnexpectedPacket,
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
			0, // version negotiation packets don't have a version
			qlog.PacketTypeVersionNegotiation,
			qlog.PacketDropUnexpectedPacket,
		)
	})
}

func testServerDroppedPacket(t *testing.T,
	conn *net.UDPConn,
	p receivedPacket,
	expectedVersion qlog.Version,
	expectedPacketType qlog.PacketType,
	expectedDropReason qlog.PacketDropReason,
) {
	readChan := make(chan struct{})
	go func() {
		defer close(readChan)
		conn.ReadFrom(make([]byte, 1000))
	}()
	var eventRecorder events.Recorder
	server := newTestServer(t, &serverOpts{eventRecorder: &eventRecorder})

	server.handlePacket(p)

	select {
	case <-readChan:
		t.Fatal("didn't expect to receive a packet")
	case <-time.After(scaleDuration(5 * time.Millisecond)):
	}

	var expectedPacketNumber protocol.PacketNumber
	if expectedPacketType != qlog.PacketTypeVersionNegotiation && expectedPacketType != "" {
		expectedPacketNumber = protocol.InvalidPacketNumber
	}

	require.Equal(t,
		[]qlogwriter.Event{
			qlog.PacketDropped{
				Header: qlog.PacketHeader{
					PacketType:   expectedPacketType,
					PacketNumber: expectedPacketNumber,
					Version:      expectedVersion,
				},
				Raw:     qlog.RawInfo{Length: int(p.Size())},
				Trigger: expectedDropReason,
			},
		},
		eventRecorder.Events(qlog.PacketDropped{}),
	)
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
	conn := newUDPConnLocalhost(t)
	var eventRecorder events.Recorder
	server := newTestServer(t, &serverOpts{
		eventRecorder:             &eventRecorder,
		disableVersionNegotiation: !enabled,
	})

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

	written := make(chan []byte, 1)
	go func() {
		b := make([]byte, 1500)
		n, _, _ := conn.ReadFrom(b)
		written <- b[:n]
	}()
	server.handlePacket(packet)

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

			require.Equal(t,
				[]qlogwriter.Event{
					qlog.VersionNegotiationSent{
						Header: qlog.PacketHeaderVersionNegotiation{
							SrcConnectionID:  src,
							DestConnectionID: dest,
						},
						SupportedVersions: server.config.Versions,
					},
				},
				eventRecorder.Events(qlog.VersionNegotiationSent{}),
			)
		case <-time.After(time.Second):
			t.Fatal("timeout")
		}
	case false:
		select {
		case <-written:
			t.Fatal("expected no version negotiation packet")
		case <-time.After(scaleDuration(10 * time.Millisecond)):
			require.Equal(t,
				[]qlogwriter.Event{
					qlog.PacketDropped{
						Header:  qlog.PacketHeader{Version: 0x42},
						Raw:     qlog.RawInfo{Length: int(packet.Size())},
						Trigger: qlog.PacketDropUnexpectedVersion,
					},
				},
				eventRecorder.Events(qlog.PacketDropped{}),
			)
		}
	}
}

func TestServerRetry(t *testing.T) {
	var eventRecorder events.Recorder
	server := newTestServer(t, &serverOpts{eventRecorder: &eventRecorder, useRetry: true})
	conn := newUDPConnLocalhost(t)

	packet := getLongHeaderPacket(t, conn.LocalAddr(),
		&wire.ExtendedHeader{
			Header: wire.Header{
				Type:             protocol.PacketTypeInitial,
				SrcConnectionID:  protocol.ParseConnectionID([]byte{1, 2, 3, 4, 5}),
				DestConnectionID: protocol.ParseConnectionID([]byte{1, 2, 3, 4, 5, 6, 7, 8}),
				Version:          protocol.Version1,
			},
			PacketNumberLen: protocol.PacketNumberLen4,
		},
		make([]byte, protocol.MinUnknownVersionPacketSize),
	)

	server.handlePacket(packet)
	checkRetry(t, conn, &eventRecorder, protocol.ParseConnectionID([]byte{1, 2, 3, 4, 5}))
}

func TestServerTokenValidation(t *testing.T) {
	var tokenGeneratorKey handshake.TokenProtectorKey
	rand.Read(tokenGeneratorKey[:])
	tg := handshake.NewTokenGenerator(tokenGeneratorKey)

	t.Run("retry token with invalid address", func(t *testing.T) {
		token, err := tg.NewRetryToken(
			&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1337},
			protocol.ConnectionID{},
			protocol.ConnectionID{},
		)
		require.NoError(t, err)
		var eventRecorder events.Recorder
		server := newTestServer(t, &serverOpts{
			useRetry:          true,
			eventRecorder:     &eventRecorder,
			tokenGeneratorKey: tokenGeneratorKey,
		})

		testServerTokenValidation(t, server, &eventRecorder, newUDPConnLocalhost(t), token, false, true, false)
	})

	t.Run("expired retry token", func(t *testing.T) {
		conn := newUDPConnLocalhost(t)
		var eventRecorder events.Recorder
		server := newTestServer(t, &serverOpts{
			useRetry:          true,
			eventRecorder:     &eventRecorder,
			config:            &Config{HandshakeIdleTimeout: time.Millisecond / 2},
			tokenGeneratorKey: tokenGeneratorKey,
		})

		token, err := tg.NewRetryToken(conn.LocalAddr(), protocol.ConnectionID{}, protocol.ConnectionID{})
		require.NoError(t, err)
		// the maximum retry token age is equivalent to the handshake timeout
		time.Sleep(time.Millisecond) // make sure the token is expired
		testServerTokenValidation(t, server, &eventRecorder, conn, token, false, true, false)
	})

	// if the packet is corrupted, it will just be dropped (no INVALID_TOKEN nor Retry is sent)
	t.Run("corrupted packet", func(t *testing.T) {
		var eventRecorder events.Recorder
		server := newTestServer(t, &serverOpts{
			useRetry:          true,
			eventRecorder:     &eventRecorder,
			config:            &Config{HandshakeIdleTimeout: time.Millisecond / 2},
			tokenGeneratorKey: tokenGeneratorKey,
		})

		conn := newUDPConnLocalhost(t)
		token, err := tg.NewRetryToken(conn.LocalAddr(), protocol.ConnectionID{}, protocol.ConnectionID{})
		require.NoError(t, err)
		time.Sleep(time.Millisecond) // make sure the token is expired
		testServerTokenValidation(t, server, &eventRecorder, conn, token, true, false, true)
	})

	t.Run("invalid non-retry token", func(t *testing.T) {
		var tokenGeneratorKey2 handshake.TokenProtectorKey
		rand.Read(tokenGeneratorKey2[:])
		var eventRecorder events.Recorder
		server := newTestServer(t, &serverOpts{
			tokenGeneratorKey: tokenGeneratorKey2, // use a different key
			useRetry:          true,
			eventRecorder:     &eventRecorder,
			maxTokenAge:       time.Millisecond,
		})

		conn := newUDPConnLocalhost(t)
		token, err := tg.NewToken(conn.LocalAddr(), 10*time.Millisecond)
		require.NoError(t, err)
		time.Sleep(3 * time.Millisecond) // make sure the token is expired
		testServerTokenValidation(t, server, &eventRecorder, conn, token, false, false, true)
	})

	t.Run("expired non-retry token", func(t *testing.T) {
		var eventRecorder events.Recorder
		server := newTestServer(t, &serverOpts{
			tokenGeneratorKey: tokenGeneratorKey,
			useRetry:          true,
			eventRecorder:     &eventRecorder,
			maxTokenAge:       time.Millisecond,
		})

		conn := newUDPConnLocalhost(t)
		token, err := tg.NewToken(conn.LocalAddr(), 100*time.Millisecond)
		require.NoError(t, err)
		time.Sleep(3 * time.Millisecond) // make sure the token is expired
		testServerTokenValidation(t, server, &eventRecorder, conn, token, false, false, true)
	})
}

func testServerTokenValidation(
	t *testing.T,
	server *testServer,
	eventRecorder *events.Recorder,
	conn *net.UDPConn,
	token []byte,
	corruptedPacket bool,
	expectInvalidTokenConnectionClose bool,
	expectRetry bool,
) {
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
	if corruptedPacket {
		packet.data[len(packet.data)-10] ^= 0xff // corrupt the packet
		server.handlePacket(packet)

		require.Eventually(t,
			func() bool { return len(eventRecorder.Events(qlog.PacketDropped{})) > 0 },
			time.Second,
			10*time.Millisecond,
		)
		require.Equal(t,
			[]qlogwriter.Event{
				qlog.PacketDropped{
					Header: qlog.PacketHeader{
						PacketType:   qlog.PacketTypeInitial,
						PacketNumber: protocol.InvalidPacketNumber,
						Version:      hdr.Version,
					},
					Raw:     qlog.RawInfo{Length: int(packet.Size())},
					Trigger: qlog.PacketDropPayloadDecryptError,
				},
			},
			eventRecorder.Events(qlog.PacketDropped{}),
		)
		return
	}

	server.handlePacket(packet)

	if expectInvalidTokenConnectionClose {
		checkConnectionClose(t, conn, eventRecorder, hdr.DestConnectionID, hdr.SrcConnectionID, qerr.InvalidToken)
	}
	if expectRetry {
		checkRetry(t, conn, eventRecorder, hdr.SrcConnectionID)
	}
}

type connConstructorArgs struct {
	ctx              context.Context
	connRunner       connRunner
	config           *Config
	origDestConnID   protocol.ConnectionID
	retrySrcConnID   *protocol.ConnectionID
	clientDestConnID protocol.ConnectionID
	destConnID       protocol.ConnectionID
	srcConnID        protocol.ConnectionID
}

type connConstructorRecorder struct {
	ch chan connConstructorArgs

	hooks []*connTestHooks
}

func newConnConstructorRecorder(hooks ...*connTestHooks) *connConstructorRecorder {
	return &connConstructorRecorder{
		ch:    make(chan connConstructorArgs, len(hooks)),
		hooks: hooks,
	}
}

func (r *connConstructorRecorder) Args() <-chan connConstructorArgs { return r.ch }

func (r *connConstructorRecorder) NewConn(
	ctx context.Context,
	_ context.CancelCauseFunc,
	_ sendConn,
	connRunner connRunner,
	origDestConnID protocol.ConnectionID,
	retrySrcConnID *protocol.ConnectionID,
	clientDestConnID protocol.ConnectionID,
	destConnID protocol.ConnectionID,
	srcConnID protocol.ConnectionID,
	_ ConnectionIDGenerator,
	_ *statelessResetter,
	config *Config,
	_ *tls.Config,
	_ *handshake.TokenGenerator,
	_ bool,
	_ time.Duration,
	_ qlogwriter.Recorder,
	_ utils.Logger,
	_ protocol.Version,
) *wrappedConn {
	r.ch <- connConstructorArgs{
		ctx:              ctx,
		connRunner:       connRunner,
		config:           config,
		origDestConnID:   origDestConnID,
		retrySrcConnID:   retrySrcConnID,
		clientDestConnID: clientDestConnID,
		destConnID:       destConnID,
		srcConnID:        srcConnID,
	}
	hooks := r.hooks[0]
	r.hooks = r.hooks[1:]
	return &wrappedConn{testHooks: hooks}
}

func TestServerCreateConnection(t *testing.T) {
	t.Run("without retry", func(t *testing.T) {
		testServerCreateConnection(t, false)
	})
	t.Run("with retry", func(t *testing.T) {
		testServerCreateConnection(t, true)
	})
}

func testServerCreateConnection(t *testing.T, useRetry bool) {
	tokenGeneratorKey := TokenGeneratorKey{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11}
	tg := handshake.NewTokenGenerator(tokenGeneratorKey)

	server := newTestServer(t, &serverOpts{
		useRetry:          useRetry,
		tokenGeneratorKey: tokenGeneratorKey,
	})

	done := make(chan struct{}, 3)
	handledPackets := make(chan receivedPacket, 1)
	recorder := newConnConstructorRecorder(&connTestHooks{
		run:               func() error { done <- struct{}{}; return nil },
		context:           func() context.Context { done <- struct{}{}; return context.Background() },
		handshakeComplete: func() <-chan struct{} { done <- struct{}{}; return make(chan struct{}) },
		handlePacket:      func(p receivedPacket) { handledPackets <- p },
	})
	server.newConn = recorder.NewConn

	conn := newUDPConnLocalhost(t)
	var token []byte
	if useRetry {
		var err error
		token, err = tg.NewRetryToken(
			conn.LocalAddr(),
			protocol.ParseConnectionID([]byte{0xde, 0xad, 0xc0, 0xde}),
			protocol.ParseConnectionID([]byte{0xde, 0xca, 0xfb, 0xad}),
		)
		require.NoError(t, err)
	}
	hdr := wire.Header{
		Type:             protocol.PacketTypeInitial,
		SrcConnectionID:  protocol.ParseConnectionID([]byte{5, 4, 3, 2, 1}),
		DestConnectionID: protocol.ParseConnectionID([]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}),
		Length:           protocol.MinInitialPacketSize + protocol.ByteCount(protocol.PacketNumberLen4) + 16,
		Token:            token,
		Version:          protocol.Version1,
	}
	packet := getLongHeaderPacketEncrypted(t,
		conn.LocalAddr(),
		&wire.ExtendedHeader{Header: hdr, PacketNumberLen: protocol.PacketNumberLen4},
		make([]byte, protocol.MinInitialPacketSize),
	)

	server.handlePacket(packet)

	select {
	case p := <-handledPackets:
		require.Equal(t, packet, p)
	case <-time.After(time.Second):
		t.Fatal("timeout")
	}

	var args connConstructorArgs
	select {
	case args = <-recorder.Args():
	case <-time.After(time.Second):
		t.Fatal("timeout")
	}

	assert.Equal(t, protocol.ParseConnectionID([]byte{5, 4, 3, 2, 1}), args.destConnID)
	assert.NotEqual(t, args.origDestConnID, args.srcConnID)
	if useRetry {
		assert.Equal(t, protocol.ParseConnectionID([]byte{5, 4, 3, 2, 1}), args.destConnID)
		assert.Equal(t, protocol.ParseConnectionID([]byte{0xde, 0xad, 0xc0, 0xde}), args.origDestConnID)
		assert.Equal(t, protocol.ParseConnectionID([]byte{0xde, 0xca, 0xfb, 0xad}), *args.retrySrcConnID)
	} else {
		assert.Equal(t, protocol.ParseConnectionID([]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}), args.origDestConnID)
		assert.Zero(t, args.retrySrcConnID)
	}

	for range 3 {
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatal("timeout")
		}
	}
}

func TestServerClose(t *testing.T) {
	var hooks []*connTestHooks
	const numConns = 3
	done := make(chan struct{}, numConns)
	for range numConns {
		hooks = append(hooks, &connTestHooks{
			closeWithTransportError: func(TransportErrorCode) { done <- struct{}{} },
		})
	}
	recorder := newConnConstructorRecorder(hooks...)
	server := newTestServer(t, &serverOpts{newConn: recorder.NewConn})

	for range numConns {
		b := make([]byte, 10)
		rand.Read(b)
		connID := protocol.ParseConnectionID(b)
		server.handlePacket(getValidInitialPacket(t,
			&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 42},
			randConnID(6),
			connID,
		))
		select {
		case <-recorder.Args():
		case <-time.After(time.Second):
			t.Fatal("timeout")
		}
	}

	server.Close()
	// closing closes all handshaking connections with CONNECTION_REFUSED
	for range numConns {
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatal("timeout")
		}
	}

	// Accept returns ErrServerClosed after closing
	for range 5 {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_, err := server.Accept(ctx)
		require.ErrorIs(t, err, ErrServerClosed)
		require.ErrorIs(t, err, net.ErrClosed)
	}
}

func TestServerGetConfigForClientAccept(t *testing.T) {
	recorder := newConnConstructorRecorder(&connTestHooks{})
	server := newTestServer(t, &serverOpts{
		config: &Config{
			GetConfigForClient: func(*ClientInfo) (*Config, error) {
				return &Config{MaxIncomingStreams: 1234}, nil
			},
		},
		newConn: recorder.NewConn,
	})

	conn := newUDPConnLocalhost(t)
	packet := getValidInitialPacket(t,
		conn.LocalAddr(),
		protocol.ParseConnectionID([]byte{5, 4, 3, 2, 1}),
		protocol.ParseConnectionID([]byte{1, 2, 3, 4, 5, 6, 7, 8}),
	)

	server.handlePacket(packet)

	var args connConstructorArgs
	select {
	case args = <-recorder.Args():
		require.EqualValues(t, 1234, args.config.MaxIncomingStreams)
	case <-time.After(time.Second):
		t.Fatal("timeout")
	}

	assert.Equal(t, protocol.ParseConnectionID([]byte{5, 4, 3, 2, 1}), args.destConnID)
	assert.NotEqual(t, args.origDestConnID, args.srcConnID)
}

func TestServerGetConfigForClientReject(t *testing.T) {
	var eventRecorder events.Recorder
	server := newTestServer(t, &serverOpts{
		eventRecorder: &eventRecorder,
		config: &Config{
			GetConfigForClient: func(*ClientInfo) (*Config, error) {
				return nil, errors.New("rejected")
			},
		},
	})

	conn := newUDPConnLocalhost(t)
	srcConnID := randConnID(6)
	destConnID := randConnID(8)
	server.handlePacket(getValidInitialPacket(t, conn.LocalAddr(), srcConnID, destConnID))

	checkConnectionClose(t, conn, &eventRecorder, destConnID, srcConnID, qerr.ConnectionRefused)
}

func TestServerReceiveQueue(t *testing.T) {
	var eventRecorder events.Recorder
	acceptConn := make(chan struct{})
	defer close(acceptConn)
	newConnChan := make(chan struct{}, protocol.MaxServerUnprocessedPackets+2)
	server := newTestServer(t, &serverOpts{
		eventRecorder: &eventRecorder,
		newConn: func(
			_ context.Context,
			_ context.CancelCauseFunc,
			_ sendConn,
			_ connRunner,
			_ protocol.ConnectionID,
			_ *protocol.ConnectionID,
			_ protocol.ConnectionID,
			_ protocol.ConnectionID,
			_ protocol.ConnectionID,
			_ ConnectionIDGenerator,
			_ *statelessResetter,
			_ *Config,
			_ *tls.Config,
			_ *handshake.TokenGenerator,
			_ bool,
			_ time.Duration,
			_ qlogwriter.Recorder,
			_ utils.Logger,
			_ protocol.Version,
		) *wrappedConn {
			newConnChan <- struct{}{}
			<-acceptConn
			return &wrappedConn{testHooks: &connTestHooks{handlePacket: func(receivedPacket) {}}}
		},
	})

	conn := newUDPConnLocalhost(t)
	for i := range protocol.MaxServerUnprocessedPackets + 1 {
		server.handlePacket(getValidInitialPacket(t, conn.LocalAddr(), randConnID(6), randConnID(8)))
		// newConn blocks on the acceptConn channel, so this blocks the server's run loop
		if i == 0 {
			select {
			case <-newConnChan:
			case <-time.After(time.Second):
				t.Fatal("timeout")
			}
		}
	}

	p := getValidInitialPacket(t, conn.LocalAddr(), randConnID(6), randConnID(8))
	server.handlePacket(p)

	require.Eventually(t,
		func() bool { return len(eventRecorder.Events(qlog.PacketDropped{})) > 0 },
		time.Second,
		10*time.Millisecond,
	)
	require.Equal(t,
		[]qlogwriter.Event{
			qlog.PacketDropped{
				Raw:     qlog.RawInfo{Length: int(p.Size())},
				Trigger: qlog.PacketDropDOSPrevention,
			},
		},
		eventRecorder.Events(qlog.PacketDropped{}),
	)
}

func TestServerAccept(t *testing.T) {
	t.Run("without accept early", func(t *testing.T) {
		testServerAccept(t, false)
	})
	t.Run("with accept early", func(t *testing.T) {
		testServerAccept(t, true)
	})
}

func testServerAccept(t *testing.T, acceptEarly bool) {
	ready := make(chan struct{})
	hooks := &connTestHooks{}
	if acceptEarly {
		hooks.earlyConnReady = func() <-chan struct{} { return ready }
	} else {
		hooks.handshakeComplete = func() <-chan struct{} { return ready }
	}
	recorder := newConnConstructorRecorder(hooks)
	server := newTestServer(t, &serverOpts{
		acceptEarly: acceptEarly,
		newConn:     recorder.NewConn,
	})

	// Accept should respect the context
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := server.Accept(ctx)
	require.ErrorIs(t, err, context.Canceled)

	// establish a new connection, which then starts handshaking
	server.handlePacket(getValidInitialPacket(t,
		&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 42},
		randConnID(6),
		randConnID(8),
	))

	accepted := make(chan error, 1)
	go func() {
		_, err := server.Accept(context.Background())
		accepted <- err
	}()

	select {
	case <-accepted:
		t.Fatal("server accepted the connection too early")
	case <-time.After(scaleDuration(5 * time.Millisecond)):
	}
	// now complete the handshake
	close(ready)

	select {
	case err := <-accepted:
		require.NoError(t, err)
	case <-time.After(time.Second):
		t.Fatal("timeout")
	}
}

func TestServerAcceptHandshakeFailure(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	recorder := newConnConstructorRecorder(&connTestHooks{
		context:           func() context.Context { return ctx },
		handshakeComplete: func() <-chan struct{} { return make(chan struct{}) },
	})
	server := newTestServer(t, &serverOpts{newConn: recorder.NewConn})

	// establish a new connection, which then starts handshaking
	server.handlePacket(getValidInitialPacket(t,
		&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 42},
		randConnID(6),
		randConnID(8),
	))

	accepted := make(chan error, 1)
	go func() {
		_, err := server.Accept(context.Background())
		accepted <- err
	}()

	cancel()
	select {
	case <-accepted:
		t.Fatal("server should not have accepted the connection")
	case <-time.After(scaleDuration(5 * time.Millisecond)):
	}
}

func TestServerAcceptQueue(t *testing.T) {
	var conns []*connTestHooks
	rejectedCloseError := make(chan TransportErrorCode, 1)
	for i := range protocol.MaxAcceptQueueSize + 2 {
		conn := &connTestHooks{
			handshakeComplete: func() <-chan struct{} {
				c := make(chan struct{})
				close(c)
				return c
			},
		}
		conns = append(conns, conn)
		if i == protocol.MaxAcceptQueueSize {
			conn.closeWithTransportError = func(code TransportErrorCode) { rejectedCloseError <- code }
			continue
		}
	}
	recorder := newConnConstructorRecorder(conns...)
	server := newTestServer(t, &serverOpts{newConn: recorder.NewConn})

	for range protocol.MaxAcceptQueueSize {
		b := make([]byte, 16)
		rand.Read(b)
		connID := protocol.ParseConnectionID(b)
		server.handlePacket(
			getValidInitialPacket(t, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 42}, randConnID(6), connID),
		)
		select {
		case args := <-recorder.Args():
			require.Equal(t, connID, args.origDestConnID)
		case <-time.After(time.Second):
			t.Fatal("timeout")
		}
	}
	// wait for the connection to be enqueued
	time.Sleep(scaleDuration(10 * time.Millisecond))

	server.handlePacket(
		getValidInitialPacket(t, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 42}, randConnID(6), randConnID(8)),
	)
	select {
	case <-recorder.Args():
	case <-time.After(time.Second):
		t.Fatal("timeout")
	}
	select {
	case code := <-rejectedCloseError:
		require.Equal(t, ConnectionRefused, code)
	case <-time.After(time.Second):
		t.Fatal("timeout")
	}

	// accept one connection, freeing up one slot in the accept queue
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_, err := server.Accept(ctx)
	require.NoError(t, err)

	// it's now possible to enqueue a new connection
	server.handlePacket(
		getValidInitialPacket(t,
			&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 42},
			randConnID(6),
			protocol.ParseConnectionID([]byte{8, 7, 6, 5, 4, 3, 2, 1}),
		),
	)
	select {
	case args := <-recorder.Args():
		require.Equal(t, protocol.ParseConnectionID([]byte{8, 7, 6, 5, 4, 3, 2, 1}), args.origDestConnID)
	case <-time.After(time.Second):
		t.Fatal("timeout")
	}
}

func TestServer0RTTReordering(t *testing.T) {
	var eventRecorder events.Recorder
	packets := make(chan receivedPacket, protocol.Max0RTTQueueLen+1)
	done := make(chan struct{})
	recorder := newConnConstructorRecorder(&connTestHooks{
		handlePacket:   func(p receivedPacket) { packets <- p },
		earlyConnReady: func() <-chan struct{} { return make(chan struct{}) },
		run:            func() error { close(done); return nil },
	})
	server := newTestServer(t, &serverOpts{
		acceptEarly:   true,
		eventRecorder: &eventRecorder,
		newConn:       recorder.NewConn,
	})

	connID := protocol.ParseConnectionID([]byte{1, 2, 3, 4, 5, 6, 7, 8})

	var zeroRTTPackets []receivedPacket

	for range protocol.Max0RTTQueueLen {
		p := getLongHeaderPacket(t,
			&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 42},
			&wire.ExtendedHeader{
				Header: wire.Header{
					Type:             protocol.PacketType0RTT,
					SrcConnectionID:  protocol.ParseConnectionID([]byte{5, 4, 3, 2, 1}),
					DestConnectionID: connID,
					Length:           100,
					Version:          protocol.Version1,
				},
				PacketNumberLen: protocol.PacketNumberLen4,
			},
			make([]byte, 100),
		)
		server.handlePacket(p)
		zeroRTTPackets = append(zeroRTTPackets, p)
	}

	// send one more packet, this one should be dropped
	p := getLongHeaderPacket(t,
		&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 42},
		&wire.ExtendedHeader{
			Header: wire.Header{
				Type:             protocol.PacketType0RTT,
				SrcConnectionID:  protocol.ParseConnectionID([]byte{5, 4, 3, 2, 1}),
				DestConnectionID: connID,
				Length:           100,
				Version:          protocol.Version1,
			},
			PacketNumberLen: protocol.PacketNumberLen4,
		},
		make([]byte, 100),
	)
	server.handlePacket(p)

	require.Eventually(t,
		func() bool { return len(eventRecorder.Events(qlog.PacketDropped{})) > 0 },
		time.Second,
		10*time.Millisecond,
	)
	require.Equal(t,
		[]qlogwriter.Event{
			qlog.PacketDropped{
				Header: qlog.PacketHeader{
					PacketType:   qlog.PacketType0RTT,
					PacketNumber: protocol.InvalidPacketNumber,
					Version:      protocol.Version1,
				},
				Raw:     qlog.RawInfo{Length: int(p.Size())},
				Trigger: qlog.PacketDropDOSPrevention,
			},
		},
		eventRecorder.Events(qlog.PacketDropped{}),
	)

	// now receive the Initial
	initial := getValidInitialPacket(t, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 42}, randConnID(5), connID)
	server.handlePacket(initial)

	for i := range protocol.Max0RTTQueueLen + 1 {
		select {
		case p := <-packets:
			if i == 0 {
				require.Equal(t, initial.data, p.data)
			} else {
				require.Equal(t, zeroRTTPackets[i-1], p)
			}
		case <-time.After(time.Second):
			t.Fatal("timeout")
		}
	}

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("timeout")
	}
}

func TestServer0RTTQueueing(t *testing.T) {
	var eventRecorder events.Recorder
	server := newTestServer(t, &serverOpts{
		acceptEarly:   true,
		eventRecorder: &eventRecorder,
	})

	firstRcvTime := monotime.Now()
	otherRcvTime := firstRcvTime.Add(protocol.Max0RTTQueueingDuration / 2)
	var sizes []protocol.ByteCount
	for i := range protocol.Max0RTTQueues {
		b := make([]byte, 16)
		rand.Read(b)
		connID := protocol.ParseConnectionID(b)
		size := protocol.ByteCount(500 + i)
		p := getLongHeaderPacket(t,
			&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 42},
			&wire.ExtendedHeader{
				Header: wire.Header{
					Type:             protocol.PacketType0RTT,
					SrcConnectionID:  protocol.ParseConnectionID([]byte{5, 4, 3, 2, 1}),
					DestConnectionID: connID,
					Length:           size,
					Version:          protocol.Version1,
				},
				PacketNumberLen: protocol.PacketNumberLen4,
			},
			make([]byte, size),
		)
		if i == 0 {
			p.rcvTime = firstRcvTime
		} else {
			p.rcvTime = otherRcvTime
		}
		sizes = append(sizes, p.Size())
		server.handlePacket(p)
	}

	// maximum number of 0-RTT queues is reached, further packets are dropped
	p := getLongHeaderPacket(t,
		&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 42},
		&wire.ExtendedHeader{
			Header: wire.Header{
				Type:             protocol.PacketType0RTT,
				SrcConnectionID:  protocol.ParseConnectionID([]byte{5, 4, 3, 2, 1}),
				DestConnectionID: protocol.ParseConnectionID([]byte{1, 2, 3, 4, 5, 6, 7, 8}),
				Length:           123,
				Version:          protocol.Version1,
			},
			PacketNumberLen: protocol.PacketNumberLen4,
		},
		make([]byte, 123),
	)
	server.handlePacket(p)
	require.Eventually(t,
		func() bool { return len(eventRecorder.Events(qlog.PacketDropped{})) > 0 },
		time.Second,
		10*time.Millisecond,
	)
	require.Equal(t,
		[]qlogwriter.Event{
			qlog.PacketDropped{
				Header: qlog.PacketHeader{
					PacketType:   qlog.PacketType0RTT,
					PacketNumber: protocol.InvalidPacketNumber,
					Version:      protocol.Version1,
				},
				Raw:     qlog.RawInfo{Length: int(p.Size())},
				Trigger: qlog.PacketDropDOSPrevention,
			},
		},
		eventRecorder.Events(qlog.PacketDropped{}),
	)
	eventRecorder.Clear()

	// There's no cleanup Go routine.
	// Cleanup is triggered when new packets are received.
	// 1. Receive one handshake packet, which triggers the cleanup of the first 0-RTT queue
	triggerPacket := getLongHeaderPacket(t,
		&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 42},
		&wire.ExtendedHeader{
			Header: wire.Header{
				Type:             protocol.PacketTypeHandshake,
				SrcConnectionID:  protocol.ParseConnectionID([]byte{5, 4, 3, 2, 1}),
				DestConnectionID: protocol.ParseConnectionID([]byte{8, 7, 6, 5, 4, 3, 2, 1}),
				Length:           123,
				Version:          protocol.Version1,
			},
			PacketNumberLen: protocol.PacketNumberLen4,
		},
		make([]byte, 123),
	)
	triggerPacket.rcvTime = firstRcvTime.Add(protocol.Max0RTTQueueingDuration + time.Nanosecond)
	server.handlePacket(triggerPacket)
	require.Eventually(t,
		func() bool { return len(eventRecorder.Events(qlog.PacketDropped{})) == 2 },
		time.Second,
		10*time.Millisecond,
	)
	require.Equal(t,
		[]qlogwriter.Event{
			qlog.PacketDropped{
				Header: qlog.PacketHeader{
					PacketType:   qlog.PacketTypeHandshake,
					PacketNumber: protocol.InvalidPacketNumber,
					Version:      protocol.Version1,
				},
				Raw:     qlog.RawInfo{Length: int(triggerPacket.Size())},
				Trigger: qlog.PacketDropUnexpectedPacket,
			},
			qlog.PacketDropped{
				Header: qlog.PacketHeader{
					PacketType:   qlog.PacketType0RTT,
					PacketNumber: protocol.InvalidPacketNumber,
					Version:      protocol.Version1,
				},
				Raw:     qlog.RawInfo{Length: int(sizes[0])},
				Trigger: qlog.PacketDropDOSPrevention,
			},
		},
		eventRecorder.Events(qlog.PacketDropped{}),
	)
	eventRecorder.Clear()

	// 2. Receive another handshake packet, which triggers the cleanup of the other 0-RTT queues
	triggerPacket = getLongHeaderPacket(t,
		&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 42},
		&wire.ExtendedHeader{
			Header: wire.Header{
				Type:             protocol.PacketTypeHandshake,
				SrcConnectionID:  protocol.ParseConnectionID([]byte{5, 4, 3, 2, 1}),
				DestConnectionID: protocol.ParseConnectionID([]byte{8, 7, 6, 5, 4, 3, 2, 1}),
				Length:           124,
				Version:          protocol.Version1,
			},
			PacketNumberLen: protocol.PacketNumberLen4,
		},
		make([]byte, 124),
	)
	triggerPacket.rcvTime = otherRcvTime.Add(protocol.Max0RTTQueueingDuration + time.Nanosecond)
	server.handlePacket(triggerPacket)

	expectedEvents := []qlogwriter.Event{
		qlog.PacketDropped{
			Header: qlog.PacketHeader{
				PacketType:   qlog.PacketTypeHandshake,
				PacketNumber: protocol.InvalidPacketNumber,
				Version:      protocol.Version1,
			},
			Raw:     qlog.RawInfo{Length: int(triggerPacket.Size())},
			Trigger: qlog.PacketDropUnexpectedPacket,
		},
	}
	for i := range protocol.Max0RTTQueues - 1 {
		expectedEvents = append(expectedEvents, qlog.PacketDropped{
			Header: qlog.PacketHeader{
				PacketType:   qlog.PacketType0RTT,
				PacketNumber: protocol.InvalidPacketNumber,
				Version:      protocol.Version1,
			},
			Raw:     qlog.RawInfo{Length: int(sizes[i+1])},
			Trigger: qlog.PacketDropDOSPrevention,
		})
	}
	require.Eventually(t,
		func() bool { return len(eventRecorder.Events(qlog.PacketDropped{})) == len(expectedEvents) },
		time.Second,
		10*time.Millisecond,
	)

	// queues are dropped in random order
	for _, event := range expectedEvents {
		require.Contains(t, eventRecorder.Events(qlog.PacketDropped{}), event)
	}
}
