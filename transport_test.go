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
	"github.com/quic-go/quic-go/internal/wire"
	"github.com/quic-go/quic-go/logging"

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

func (h *mockPacketHandler) handlePacket(p receivedPacket)                        { h.packets <- p }
func (h *mockPacketHandler) destroy(err error)                                    { h.destruction <- err }
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
	return b
}

func TestTransportPacketHandling(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	phm := NewMockPacketHandlerManager(mockCtrl)

	tr := &Transport{
		Conn:       newUPDConnLocalhost(t),
		handlerMap: phm,
	}
	tr.init(true)
	defer func() {
		phm.EXPECT().Close(gomock.Any())
		tr.Close()
	}()

	connID1 := protocol.ParseConnectionID([]byte{1, 2, 3, 4, 5, 6, 7, 8})
	connID2 := protocol.ParseConnectionID([]byte{8, 7, 6, 5, 4, 3, 2, 1})

	connChan1 := make(chan receivedPacket, 1)
	conn1 := &mockPacketHandler{packets: connChan1}
	phm.EXPECT().Get(connID1).Return(conn1, true)
	connChan2 := make(chan receivedPacket, 1)
	conn2 := &mockPacketHandler{packets: connChan2}
	phm.EXPECT().Get(connID2).Return(conn2, true)

	conn := newUPDConnLocalhost(t)
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
	// try 10 times to trigger race conditions
	for i := 0; i < 10; i++ {
		tr := &Transport{Conn: newUPDConnLocalhost(t)}
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
}

func TestTransportErrFromConn(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	phm := NewMockPacketHandlerManager(mockCtrl)
	readErrChan := make(chan error, 2)
	conn := &mockPacketConn{readErrs: readErrChan, localAddr: &net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 1234}}
	tr := Transport{Conn: conn, handlerMap: phm}
	defer tr.Close()

	tr.init(true)
	tr.handlerMap = phm

	// temporary errors don't lead to a shutdown...
	var tempErr deadlineError
	require.True(t, tempErr.Temporary())
	readErrChan <- tempErr
	// don't expect any calls to phm.Close
	time.Sleep(scaleDuration(20 * time.Millisecond))

	// ...but non-temporary errors do
	done := make(chan struct{})
	phm.EXPECT().Close(gomock.Any()).Do(func(error) { close(done) })
	readErrChan <- errors.New("read failed")
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("timeout")
	}

	// TODO(#4778): test that it's not possible to listen after the transport is closed
}

func TestTransportStatelessResetReceiving(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	phm := NewMockPacketHandlerManager(mockCtrl)
	tr := &Transport{
		Conn:               newUPDConnLocalhost(t),
		ConnectionIDLength: 4,
		handlerMap:         phm,
	}
	tr.init(true)
	defer func() {
		phm.EXPECT().Close(gomock.Any())
		tr.Close()
	}()

	// TODO(#4781): test that packets too short to be stateless resets are dropped

	connID := protocol.ParseConnectionID([]byte{9, 10, 11, 12})
	// now send a packet with a connection ID that doesn't exist
	token := protocol.StatelessResetToken{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	b, err := wire.AppendShortHeader(nil, connID, 1337, 2, protocol.KeyPhaseOne)
	require.NoError(t, err)
	b = append(b, token[:]...)

	destroyChan := make(chan error, 1)
	conn1 := &mockPacketHandler{destruction: destroyChan}
	gomock.InOrder(
		phm.EXPECT().Get(connID), // no handler for this connection ID
		phm.EXPECT().GetByResetToken(token).Return(conn1, true),
	)

	conn := newUPDConnLocalhost(t)
	_, err = conn.WriteTo(b, tr.Conn.LocalAddr())
	require.NoError(t, err)

	select {
	case err := <-destroyChan:
		require.Error(t, err)
	case <-time.After(time.Second):
		t.Fatal("timeout")
	}
}

func TestTransportStatelessResetSending(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	phm := NewMockPacketHandlerManager(mockCtrl)
	tr := &Transport{
		Conn:               newUPDConnLocalhost(t),
		ConnectionIDLength: 4,
		StatelessResetKey:  &StatelessResetKey{1, 2, 3, 4},
		handlerMap:         phm,
	}
	tr.init(true)
	defer func() {
		phm.EXPECT().Close(gomock.Any())
		tr.Close()
	}()

	connID := protocol.ParseConnectionID([]byte{9, 10, 11, 12})
	phm.EXPECT().Get(connID).Times(2) // no handler for this connection ID
	phm.EXPECT().GetByResetToken(gomock.Any()).Times(2)

	// now send a packet with a connection ID that doesn't exist
	b, err := wire.AppendShortHeader(nil, connID, 1337, 2, protocol.KeyPhaseOne)
	require.NoError(t, err)

	conn := newUPDConnLocalhost(t)

	// no stateless reset sent for packets smaller than MinStatelessResetSize
	_, err = conn.WriteTo(append(b, make([]byte, protocol.MinStatelessResetSize-len(b))...), tr.Conn.LocalAddr())
	require.NoError(t, err)
	conn.SetReadDeadline(time.Now().Add(scaleDuration(10 * time.Millisecond)))
	_, _, err = conn.ReadFrom(make([]byte, 1024))
	require.Error(t, err)
	require.ErrorIs(t, err, os.ErrDeadlineExceeded)

	// no stateless reset sent for packets smaller than MinStatelessResetSize
	token := protocol.StatelessResetToken{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	phm.EXPECT().GetStatelessResetToken(connID).Return(token)
	_, err = conn.WriteTo(append(b, make([]byte, protocol.MinStatelessResetSize-len(b)+1)...), tr.Conn.LocalAddr())
	require.NoError(t, err)
	conn.SetReadDeadline(time.Now().Add(time.Second))
	p := make([]byte, 1024)
	n, addr, err := conn.ReadFrom(p)
	require.NoError(t, err)
	require.Equal(t, addr, tr.Conn.LocalAddr())
	require.Contains(t, string(p[:n]), string(token[:]))
}

func TestTransportDropsUnparseableQUICPackets(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	mockTracer, tracer := mocklogging.NewMockTracer(mockCtrl)
	tr := &Transport{
		Conn:               newUPDConnLocalhost(t),
		ConnectionIDLength: 10,
		Tracer:             mockTracer,
	}
	require.NoError(t, tr.init(true))
	defer func() {
		tracer.EXPECT().Close()
		tr.Close()
	}()

	conn := newUPDConnLocalhost(t)

	dropped := make(chan struct{})
	tracer.EXPECT().DroppedPacket(conn.LocalAddr(), logging.PacketTypeNotDetermined, protocol.ByteCount(4), logging.PacketDropHeaderParseError).Do(
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

func TestTransportSingleListener(t *testing.T) {
	tr := &Transport{Conn: newUPDConnLocalhost(t)}
	require.NoError(t, tr.init(true))
	defer tr.Close()

	// TODO(#4779): test that packets are dropped if no listener is set

	ln, err := tr.Listen(&tls.Config{}, nil)
	require.NoError(t, err)

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
	tr := &Transport{Conn: newUPDConnLocalhost(t)}
	defer tr.Close()

	ctx, cancel := context.WithTimeout(context.Background(), scaleDuration(5*time.Millisecond))
	defer cancel()
	_, _, err := tr.ReadNonQUICPacket(ctx, make([]byte, 1024))
	require.Error(t, err)
	require.ErrorIs(t, err, context.DeadlineExceeded)

	conn := newUPDConnLocalhost(t)
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

func (c *faultySyscallConn) SyscallConn() (syscall.RawConn, error) { return nil, errors.New("mocked") }

func TestTransportFaultySyscallConn(t *testing.T) {
	syscallconn := &faultySyscallConn{PacketConn: newUPDConnLocalhost(t)}

	tr := &Transport{Conn: syscallconn}
	_, err := tr.Listen(&tls.Config{}, nil)
	require.Error(t, err)
	require.ErrorContains(t, err, "mocked")

	conns := getMultiplexer().(*connMultiplexer).conns
	require.Empty(t, conns)
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
