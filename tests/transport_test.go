package quic

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"net"
	"os"
	"syscall"
	"testing"
	"time"

	mocklogging "github.com/quic-go/quic-go/internal/mocks/logging"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/qerr"
	"github.com/quic-go/quic-go/internal/utils"
	"github.com/quic-go/quic-go/internal/wire"
	"github.com/quic-go/quic-go/logging"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

type mockPacketConn struct {
	localAddr net.Addr
	readErrs  chan error
}

func (c *mockPacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	err, ok := <-c.readErrs
	if !ok {
		return 0, nil, net.ErrClosed
	}
	return 0, nil, err
}

func (c *mockPacketConn) WriteTo(p []byte, addr net.Addr) (n int, err error) { panic("implement me") }
func (c *mockPacketConn) LocalAddr() net.Addr                                { return c.localAddr }
func (c *mockPacketConn) Close() error                                       { close(c.readErrs); return nil }
func (c *mockPacketConn) SetDeadline(t time.Time) error                      { return nil }
func (c *mockPacketConn) SetReadDeadline(t time.Time) error                  { return nil }
func (c *mockPacketConn) SetWriteDeadline(t time.Time) error                 { return nil }

type mockPacketHandler struct {
	packets     chan<- receivedPacket
	destruction chan<- error
}

func (h *mockPacketHandler) handlePacket(p receivedPacket) {
	h.packets <- p
}

func (h *mockPacketHandler) destroy(err error) {
	if h.destruction != nil {
		h.destruction <- err
	}
}

func (h *mockPacketHandler) closeWithTransportError(code qerr.TransportErrorCode) {}

func getPacket(t *testing.T, connID protocol.ConnectionID) []byte {
	return getPacketWithPacketType(t, connID, protocol.PacketTypeHandshake, 2)
}

func getPacketWithPacketType(t *testing.T, connID protocol.ConnectionID, typ protocol.PacketType, length protocol.ByteCount) []byte {
	t.Helper()
	b, err := (&wire.ExtendedHeader{
		Header: wire.Header{
			Type:             typ,
			DestConnectionID: connID,
			Length:           length,
			Version:          protocol.Version1,
		},
		PacketNumberLen: protocol.PacketNumberLen2,
	}).Append(nil, protocol.Version1)
	require.NoError(t, err)
	return append(b, bytes.Repeat([]byte{42}, int(length)-2)...)
}

func TestTransportPacketHandling(t *testing.T) {
	tr := &Transport{Conn: newUDPConnLocalhost(t)}
	tr.init(true)
	defer tr.Close()

	connID1 := protocol.ParseConnectionID([]byte{1, 2, 3, 4, 5, 6, 7, 8})
	connID2 := protocol.ParseConnectionID([]byte{8, 7, 6, 5, 4, 3, 2, 1})

	connChan1 := make(chan receivedPacket, 1)
	conn1 := &mockPacketHandler{packets: connChan1}
	(*packetHandlerMap)(tr).Add(connID1, conn1)
	connChan2 := make(chan receivedPacket, 1)
	conn2 := &mockPacketHandler{packets: connChan2}
	(*packetHandlerMap)(tr).Add(connID2, conn2)

	conn := newUDPConnLocalhost(t)
	_, err := conn.WriteTo(getPacket(t, connID1), tr.Conn.LocalAddr())
	require.NoError(t, err)
	_, err = conn.WriteTo(getPacket(t, connID2), tr.Conn.LocalAddr())
	require.NoError(t, err)

	select {
	case p := <-connChan1:
		require.Equal(t, conn.LocalAddr(), p.remoteAddr)
		connID, err := wire.ParseConnectionID(p.data, 0)
		require.NoError(t, err)
		require.Equal(t, connID1, connID)
	case <-time.After(time.Second):
		t.Fatal("timeout")
	}
	select {
	case p := <-connChan2:
		require.Equal(t, conn.LocalAddr(), p.remoteAddr)
		connID, err := wire.ParseConnectionID(p.data, 0)
		require.NoError(t, err)
		require.Equal(t, connID2, connID)
	case <-time.After(time.Second):
		t.Fatal("timeout")
	}
}

func TestTransportAndListenerConcurrentClose(t *testing.T) {
	tr := &Transport{Conn: newUDPConnLocalhost(t)}
	ln, err := tr.Listen(&tls.Config{}, nil)
	require.NoError(t, err)
	// close transport and listener concurrently
	lnErrChan := make(chan error, 1)
	go func() { lnErrChan <- ln.Close() }()
	require.NoError(t, tr.Close())
	select {
	case err := <-lnErrChan:
		require.NoError(t, err)
	case <-time.After(time.Second):
		t.Fatal("timeout")
	}
}

func TestTransportAndDialConcurrentClose(t *testing.T) {
	server := newUDPConnLocalhost(t)

	tr := &Transport{Conn: newUDPConnLocalhost(t)}
	// close transport and dial concurrently
	errChan := make(chan error, 1)
	go func() { errChan <- tr.Close() }()
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	_, err := tr.Dial(ctx, server.LocalAddr(), &tls.Config{}, nil)
	require.Error(t, err)
	require.ErrorIs(t, err, ErrTransportClosed)
	require.NotErrorIs(t, err, context.DeadlineExceeded)

	select {
	case <-errChan:
	case <-time.After(time.Second):
		t.Fatal("timeout")
	}
}

func TestTransportErrFromConn(t *testing.T) {
	t.Setenv("QUIC_GO_DISABLE_RECEIVE_BUFFER_WARNING", "true")

	readErrChan := make(chan error, 2)
	tr := Transport{
		Conn: &mockPacketConn{
			readErrs:  readErrChan,
			localAddr: &net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 1234},
		},
	}
	defer tr.Close()
	tr.init(true)

	errChan := make(chan error, 1)
	ph := &mockPacketHandler{destruction: errChan}
	(*packetHandlerMap)(&tr).Add(protocol.ParseConnectionID([]byte{1, 2, 3, 4}), ph)

	// temporary errors don't lead to a shutdown...
	var tempErr deadlineError
	require.True(t, tempErr.Temporary())
	readErrChan <- tempErr
	// don't expect any calls to phm.Close
	time.Sleep(scaleDuration(10 * time.Millisecond))

	// ...but non-temporary errors do
	readErrChan <- errors.New("read failed")
	select {
	case err := <-errChan:
		require.ErrorIs(t, err, ErrTransportClosed)
	case <-time.After(time.Second):
		t.Fatal("timeout")
	}

	_, err := tr.Listen(&tls.Config{}, nil)
	require.ErrorIs(t, err, ErrTransportClosed)
}

func TestTransportStatelessResetReceiving(t *testing.T) {
	tr := &Transport{
		Conn:               newUDPConnLocalhost(t),
		ConnectionIDLength: 4,
	}
	tr.init(true)
	defer tr.Close()

	connID := protocol.ParseConnectionID([]byte{9, 10, 11, 12})
	// now send a packet with a connection ID that doesn't exist
	token := protocol.StatelessResetToken{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	b, err := wire.AppendShortHeader(nil, connID, 1337, 2, protocol.KeyPhaseOne)
	require.NoError(t, err)
	b = append(b, token[:]...)

	destroyChan := make(chan error, 1)
	conn1 := &mockPacketHandler{destruction: destroyChan}
	(*packetHandlerMap)(tr).AddResetToken(token, conn1)

	conn := newUDPConnLocalhost(t)
	_, err = conn.WriteTo(b, tr.Conn.LocalAddr())
	require.NoError(t, err)

	select {
	case err := <-destroyChan:
		require.ErrorIs(t, err, &qerr.StatelessResetError{})
	case <-time.After(time.Second):
		t.Fatal("timeout")
	}
}

func TestTransportStatelessResetSending(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	tracer, mockTracer := mocklogging.NewMockTracer(mockCtrl)
	tr := &Transport{
		Conn:               newUDPConnLocalhost(t),
		ConnectionIDLength: 4,
		StatelessResetKey:  &StatelessResetKey{1, 2, 3, 4},
		Tracer:             tracer,
	}
	tr.init(true)
	defer func() {
		mockTracer.EXPECT().Close()
		tr.Close()
	}()

	connID := protocol.ParseConnectionID([]byte{9, 10, 11, 12})

	// now send a packet with a connection ID that doesn't exist
	b, err := wire.AppendShortHeader(nil, connID, 1337, 2, protocol.KeyPhaseOne)
	require.NoError(t, err)

	conn := newUDPConnLocalhost(t)

	// no stateless reset sent for packets smaller than MinStatelessResetSize
	dropped := make(chan struct{})
	smallPacket := append(b, make([]byte, protocol.MinStatelessResetSize-len(b))...)
	mockTracer.EXPECT().DroppedPacket(conn.LocalAddr(), logging.PacketTypeNotDetermined, protocol.ByteCount(len(smallPacket)), logging.PacketDropUnknownConnectionID).Do(
		func(net.Addr, logging.PacketType, protocol.ByteCount, logging.PacketDropReason) { close(dropped) },
	)
	_, err = conn.WriteTo(smallPacket, tr.Conn.LocalAddr())
	require.NoError(t, err)
	select {
	case <-dropped:
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for packet to be dropped")
	}
	require.True(t, mockCtrl.Satisfied())

	// but a stateless reset is sent for packets larger than MinStatelessResetSize
	_, err = conn.WriteTo(append(b, make([]byte, protocol.MinStatelessResetSize-len(b)+1)...), tr.Conn.LocalAddr())
	require.NoError(t, err)
	conn.SetReadDeadline(time.Now().Add(time.Second))
	p := make([]byte, 1024)
	n, addr, err := conn.ReadFrom(p)
	require.NoError(t, err)
	require.Equal(t, addr, tr.Conn.LocalAddr())
	srt := newStatelessResetter(tr.StatelessResetKey).GetStatelessResetToken(connID)
	require.Contains(t, string(p[:n]), string(srt[:]))
}

func TestTransportUnparseableQUICPackets(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	tracer, mockTracer := mocklogging.NewMockTracer(mockCtrl)
	tr := &Transport{
		Conn:               newUDPConnLocalhost(t),
		ConnectionIDLength: 10,
		Tracer:             tracer,
	}
	require.NoError(t, tr.init(true))
	defer func() {
		mockTracer.EXPECT().Close()
		tr.Close()
	}()

	conn := newUDPConnLocalhost(t)

	dropped := make(chan struct{})
	mockTracer.EXPECT().DroppedPacket(conn.LocalAddr(), logging.PacketTypeNotDetermined, protocol.ByteCount(4), logging.PacketDropHeaderParseError).Do(
		func(net.Addr, logging.PacketType, protocol.ByteCount, logging.PacketDropReason) { close(dropped) },
	)
	_, err := conn.WriteTo([]byte{0x40 /* set the QUIC bit */, 1, 2, 3}, tr.Conn.LocalAddr())
	require.NoError(t, err)
	select {
	case <-dropped:
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for packet to be dropped")
	}
}

func TestTransportListening(t *testing.T) {
	tracer, mockTracer := mocklogging.NewMockTracer(gomock.NewController(t))
	tr := &Transport{
		Conn:               newUDPConnLocalhost(t),
		ConnectionIDLength: 5,
		Tracer:             tracer,
	}
	require.NoError(t, tr.init(true))
	defer func() {
		mockTracer.EXPECT().Close()
		tr.Close()
	}()

	conn := newUDPConnLocalhost(t)
	data := wire.ComposeVersionNegotiation([]byte{1, 2, 3, 4, 5}, []byte{6, 7, 8, 9, 10}, []protocol.Version{protocol.Version1})
	dropped := make(chan struct{}, 10)
	mockTracer.EXPECT().DroppedPacket(conn.LocalAddr(), logging.PacketTypeNotDetermined, protocol.ByteCount(len(data)), logging.PacketDropUnknownConnectionID).Do(
		func(net.Addr, logging.PacketType, protocol.ByteCount, logging.PacketDropReason) {
			dropped <- struct{}{}
		},
	)

	_, err := conn.WriteTo(data, tr.Conn.LocalAddr())
	require.NoError(t, err)
	select {
	case <-dropped:
	case <-time.After(time.Second):
		t.Fatal("timeout")
	}

	ln, err := tr.Listen(&tls.Config{}, nil)
	require.NoError(t, err)

	// send the packet again
	lnDropped := make(chan struct{}, 10)
	mockTracer.EXPECT().DroppedPacket(conn.LocalAddr(), logging.PacketTypeVersionNegotiation, protocol.ByteCount(len(data)), logging.PacketDropUnexpectedPacket).Do(
		func(net.Addr, logging.PacketType, protocol.ByteCount, logging.PacketDropReason) {
			lnDropped <- struct{}{}
		},
	)

	_, err = conn.WriteTo(data, tr.Conn.LocalAddr())
	require.NoError(t, err)
	select {
	case <-lnDropped:
	case <-dropped:
		t.Fatal("packet should have been handled by the listener")
	case <-time.After(time.Second):
		t.Fatal("timeout")
	}

	// only a single listener can be set
	_, err = tr.Listen(&tls.Config{}, nil)
	require.Error(t, err)
	require.ErrorIs(t, err, errListenerAlreadySet)

	require.NoError(t, ln.Close())
	// now it's possible to add a new listener
	ln, err = tr.Listen(&tls.Config{}, nil)
	require.NoError(t, err)
	defer ln.Close()
}

func TestTransportNonQUICPackets(t *testing.T) {
	tr := &Transport{Conn: newUDPConnLocalhost(t)}
	defer tr.Close()

	ctx, cancel := context.WithTimeout(context.Background(), scaleDuration(5*time.Millisecond))
	defer cancel()
	_, _, err := tr.ReadNonQUICPacket(ctx, make([]byte, 1024))
	require.Error(t, err)
	require.ErrorIs(t, err, context.DeadlineExceeded)

	conn := newUDPConnLocalhost(t)
	data := []byte{0 /* don't set the QUIC bit */, 1, 2, 3}
	_, err = conn.WriteTo(data, tr.Conn.LocalAddr())
	require.NoError(t, err)
	_, err = conn.WriteTo(data, tr.Conn.LocalAddr())
	require.NoError(t, err)

	ctx, cancel = context.WithTimeout(context.Background(), scaleDuration(time.Second))
	defer cancel()
	b := make([]byte, 1024)
	n, addr, err := tr.ReadNonQUICPacket(ctx, b)
	require.NoError(t, err)
	require.Equal(t, data, b[:n])
	require.Equal(t, addr, conn.LocalAddr())

	// now send a lot of packets without reading them
	for i := range 2 * maxQueuedNonQUICPackets {
		data := append([]byte{0 /* don't set the QUIC bit */, uint8(i)}, bytes.Repeat([]byte{uint8(i)}, 1000)...)
		_, err = conn.WriteTo(data, tr.Conn.LocalAddr())
		require.NoError(t, err)
	}
	time.Sleep(scaleDuration(10 * time.Millisecond))

	var received int
	for {
		ctx, cancel = context.WithTimeout(context.Background(), scaleDuration(20*time.Millisecond))
		defer cancel()
		_, _, err := tr.ReadNonQUICPacket(ctx, b)
		if errors.Is(err, context.DeadlineExceeded) {
			break
		}
		require.NoError(t, err)
		received++
	}
	require.Equal(t, received, maxQueuedNonQUICPackets)
}

type faultySyscallConn struct{ net.PacketConn }

func (c *faultySyscallConn) SyscallConn() (syscall.RawConn, error) { return nil, assert.AnError }

func TestTransportFaultySyscallConn(t *testing.T) {
	syscallconn := &faultySyscallConn{PacketConn: newUDPConnLocalhost(t)}

	tr := &Transport{Conn: syscallconn}
	_, err := tr.Listen(&tls.Config{}, nil)
	require.Error(t, err)
	require.ErrorIs(t, err, assert.AnError)
}

func TestTransportSetTLSConfigServerName(t *testing.T) {
	for _, tt := range []struct {
		name     string
		expected string
		conf     *tls.Config
		host     string
	}{
		{
			name:     "uses the value from the config",
			expected: "foo.bar",
			conf:     &tls.Config{ServerName: "foo.bar"},
			host:     "baz.foo",
		},
		{
			name:     "uses the hostname",
			expected: "golang.org",
			conf:     &tls.Config{},
			host:     "golang.org",
		},
		{
			name:     "removes the port from the hostname",
			expected: "golang.org",
			conf:     &tls.Config{},
			host:     "golang.org:1234",
		},
		{
			name:     "uses the IP",
			expected: "1.3.5.7",
			conf:     &tls.Config{},
			host:     "",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			setTLSConfigServerName(tt.conf, &net.UDPAddr{IP: net.IPv4(1, 3, 5, 7), Port: 1234}, tt.host)
			require.Equal(t, tt.expected, tt.conf.ServerName)
		})
	}
}

func TestTransportDial(t *testing.T) {
	t.Run("regular", func(t *testing.T) {
		testTransportDial(t, false)
	})

	t.Run("early", func(t *testing.T) {
		testTransportDial(t, true)
	})
}

func testTransportDial(t *testing.T, early bool) {
	originalClientConnConstructor := newClientConnection
	t.Cleanup(func() { newClientConnection = originalClientConnConstructor })

	mockCtrl := gomock.NewController(t)
	conn := NewMockQUICConn(mockCtrl)
	handshakeChan := make(chan struct{})
	if early {
		conn.EXPECT().earlyConnReady().Return(handshakeChan)
		conn.EXPECT().HandshakeComplete().Return(make(chan struct{}))
	} else {
		conn.EXPECT().HandshakeComplete().Return(handshakeChan)
	}
	blockRun := make(chan struct{})
	conn.EXPECT().run().DoAndReturn(func() error {
		<-blockRun
		return errors.New("done")
	})
	defer close(blockRun)

	newClientConnection = func(
		_ context.Context,
		_ sendConn,
		_ connRunner,
		_ protocol.ConnectionID,
		_ protocol.ConnectionID,
		_ ConnectionIDGenerator,
		_ *statelessResetter,
		_ *Config,
		_ *tls.Config,
		_ protocol.PacketNumber,
		_ bool,
		_ bool,
		_ *logging.ConnectionTracer,
		_ utils.Logger,
		_ protocol.Version,
	) quicConn {
		return conn
	}

	tr := &Transport{Conn: newUDPConnLocalhost(t)}
	tr.init(true)
	defer tr.Close()

	errChan := make(chan error, 1)
	go func() {
		var err error
		if early {
			_, err = tr.DialEarly(context.Background(), nil, &tls.Config{}, nil)
		} else {
			_, err = tr.Dial(context.Background(), nil, &tls.Config{}, nil)
		}
		errChan <- err
	}()

	select {
	case <-errChan:
		t.Fatal("Dial shouldn't have returned")
	case <-time.After(scaleDuration(10 * time.Millisecond)):
	}

	close(handshakeChan)
	select {
	case err := <-errChan:
		require.NoError(t, err)
	case <-time.After(time.Second):
	}

	// for test tear-down
	conn.EXPECT().destroy(gomock.Any()).AnyTimes()
}

func TestTransportDialingVersionNegotiation(t *testing.T) {
	originalClientConnConstructor := newClientConnection
	t.Cleanup(func() { newClientConnection = originalClientConnConstructor })

	// connID := protocol.ParseConnectionID([]byte{1, 2, 3, 4, 5, 6, 7, 8})
	mockCtrl := gomock.NewController(t)
	// runner := NewMockConnRunner(mockCtrl)
	conn := NewMockQUICConn(mockCtrl)
	conn.EXPECT().HandshakeComplete().Return(make(chan struct{}))
	conn.EXPECT().run().Return(&errCloseForRecreating{nextPacketNumber: 109, nextVersion: 789})

	conn2 := NewMockQUICConn(mockCtrl)
	conn2.EXPECT().HandshakeComplete().Return(make(chan struct{}))
	conn2.EXPECT().run().Return(assert.AnError)

	type connParams struct {
		pn                   protocol.PacketNumber
		hasNegotiatedVersion bool
		version              protocol.Version
	}

	connChan := make(chan connParams, 2)
	var counter int
	newClientConnection = func(
		_ context.Context,
		_ sendConn,
		_ connRunner,
		_ protocol.ConnectionID,
		_ protocol.ConnectionID,
		_ ConnectionIDGenerator,
		_ *statelessResetter,
		_ *Config,
		_ *tls.Config,
		pn protocol.PacketNumber,
		_ bool,
		hasNegotiatedVersion bool,
		_ *logging.ConnectionTracer,
		_ utils.Logger,
		v protocol.Version,
	) quicConn {
		connChan <- connParams{pn: pn, hasNegotiatedVersion: hasNegotiatedVersion, version: v}
		if counter == 0 {
			counter++
			return conn
		}
		return conn2
	}

	tr := &Transport{Conn: newUDPConnLocalhost(t)}
	tr.init(true)
	defer tr.Close()

	_, err := tr.Dial(context.Background(), nil, &tls.Config{}, nil)
	require.ErrorIs(t, err, assert.AnError)

	select {
	case params := <-connChan:
		require.Zero(t, params.pn)
		require.False(t, params.hasNegotiatedVersion)
		require.Equal(t, protocol.Version1, params.version)
	case <-time.After(time.Second):
		t.Fatal("timeout")
	}
	select {
	case params := <-connChan:
		require.Equal(t, protocol.PacketNumber(109), params.pn)
		require.True(t, params.hasNegotiatedVersion)
		require.Equal(t, protocol.Version(789), params.version)
	case <-time.After(time.Second):
		t.Fatal("timeout")
	}

	// for test tear down
	conn.EXPECT().destroy(gomock.Any()).AnyTimes()
	conn2.EXPECT().destroy(gomock.Any()).AnyTimes()
}

func TestTransportReplaceWithClosed(t *testing.T) {
	t.Run("local", func(t *testing.T) {
		testTransportReplaceWithClosed(t, true)
	})
	t.Run("remote", func(t *testing.T) {
		testTransportReplaceWithClosed(t, false)
	})
}

func testTransportReplaceWithClosed(t *testing.T, local bool) {
	srk := StatelessResetKey{1, 2, 3, 4}
	tr := &Transport{
		Conn:               newUDPConnLocalhost(t),
		ConnectionIDLength: 4,
		StatelessResetKey:  &srk,
	}
	tr.init(true)
	defer tr.Close()

	dur := scaleDuration(10 * time.Millisecond)

	var closePacket []byte
	if local {
		closePacket = []byte("foobar")
	}

	handler := &mockPacketHandler{}
	connID := protocol.ParseConnectionID([]byte{4, 3, 2, 1})
	m := (*packetHandlerMap)(tr)
	require.True(t, m.Add(connID, handler))
	start := time.Now()
	m.ReplaceWithClosed([]protocol.ConnectionID{connID}, closePacket, dur)

	p := make([]byte, 100)
	p[0] = 0x40 // QUIC bit
	copy(p[1:], connID.Bytes())

	conn := newUDPConnLocalhost(t)
	var sent int
	for now := range time.NewTicker(dur / 20).C {
		_, err := conn.WriteTo(p, tr.Conn.LocalAddr())
		require.NoError(t, err)
		sent++
		if now.After(start.Add(dur)) {
			break
		}
	}
	// For locally closed connections, CONNECTION_CLOSE packets are sent with an exponential backoff
	for i := 0; i*i < sent; i++ {
		conn.SetReadDeadline(time.Now().Add(time.Second))
		b := make([]byte, 100)
		if local {
			n, _, err := conn.ReadFrom(b)
			require.NoError(t, err)
			require.Equal(t, []byte("foobar"), b[:n])
		}
	}
	// Afterwards, we receive a stateless reset, not a copy of the CONNECTION_CLOSE packet.
	// Retry up to 3 times, the connection is deleted from the map on a timer.
	for i := 0; i < 3; i++ {
		_, err := conn.WriteTo(p, tr.Conn.LocalAddr())
		require.NoError(t, err)
		conn.SetReadDeadline(time.Now().Add(dur / 4))
		b := make([]byte, 100)
		n, _, err := conn.ReadFrom(b)
		if errors.Is(err, os.ErrDeadlineExceeded) {
			continue
		}
		require.NoError(t, err)
		require.NotEqual(t, []byte("foobar"), b[:n])
		require.GreaterOrEqual(t, n, protocol.MinStatelessResetSize)
		break
	}
}
