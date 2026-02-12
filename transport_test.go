package quic

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"math"
	"net"
	"sync/atomic"
	"syscall"
	"testing"
	"testing/synctest"
	"time"

	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/qerr"
	"github.com/quic-go/quic-go/internal/utils"
	"github.com/quic-go/quic-go/internal/wire"
	"github.com/quic-go/quic-go/qlog"
	"github.com/quic-go/quic-go/qlogwriter"
	"github.com/quic-go/quic-go/testutils/events"
	"github.com/quic-go/quic-go/testutils/simnet"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

func newSimnetLink(t *testing.T, rtt time.Duration) (client, server net.PacketConn, close func()) {
	t.Helper()

	n := &simnet.Simnet{Router: &simnet.PerfectRouter{}}
	settings := simnet.NodeBiDiLinkSettings{Latency: rtt / 2}

	client = n.NewEndpoint(&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9001}, settings)
	server = n.NewEndpoint(&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9002}, settings)
	require.NoError(t, n.Start())
	return client, server, func() {
		require.NoError(t, n.Close())
	}
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

	synctest.Test(t, func(t *testing.T) {
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
		synctest.Wait()

		// ...but non-temporary errors do
		readErrChan <- errors.New("read failed")
		synctest.Wait()

		select {
		case err := <-errChan:
			require.ErrorIs(t, err, ErrTransportClosed)
		case <-time.After(time.Second):
			t.Fatal("timeout")
		}

		_, err := tr.Listen(&tls.Config{}, nil)
		require.ErrorIs(t, err, ErrTransportClosed)
	})
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
	synctest.Test(t, func(t *testing.T) {
		const rtt = 10 * time.Millisecond
		clientConn, serverConn, closeFn := newSimnetLink(t, rtt)
		defer closeFn()

		var eventRecorder events.Recorder
		tr := &Transport{
			Conn:               serverConn,
			ConnectionIDLength: 4,
			StatelessResetKey:  &StatelessResetKey{1, 2, 3, 4},
			Tracer:             &eventRecorder,
		}
		tr.init(true)
		defer tr.Close()

		connID := protocol.ParseConnectionID([]byte{9, 10, 11, 12})

		// now send a packet with a connection ID that doesn't exist
		b, err := wire.AppendShortHeader(nil, connID, 1337, 2, protocol.KeyPhaseOne)
		require.NoError(t, err)

		// no stateless reset sent for packets smaller than MinStatelessResetSize
		smallPacket := append(b, make([]byte, protocol.MinStatelessResetSize-len(b))...)
		_, err = clientConn.WriteTo(smallPacket, tr.Conn.LocalAddr())
		require.NoError(t, err)

		time.Sleep(rtt) // so that the packet arrives at the server

		require.Equal(t,
			[]qlogwriter.Event{
				qlog.PacketDropped{
					Header:  qlog.PacketHeader{PacketType: qlog.PacketType1RTT},
					Raw:     qlog.RawInfo{Length: len(smallPacket)},
					Trigger: qlog.PacketDropUnknownConnectionID,
				},
			},
			eventRecorder.Events(qlog.PacketDropped{}),
		)

		// but a stateless reset is sent for packets larger than MinStatelessResetSize
		_, err = clientConn.WriteTo(append(b, make([]byte, protocol.MinStatelessResetSize-len(b)+1)...), tr.Conn.LocalAddr())
		require.NoError(t, err)
		clientConn.SetReadDeadline(time.Now().Add(time.Second))
		p := make([]byte, 1024)
		n, addr, err := clientConn.ReadFrom(p)
		require.NoError(t, err)
		require.Equal(t, addr, tr.Conn.LocalAddr())
		srt := newStatelessResetter(tr.StatelessResetKey).GetStatelessResetToken(connID)
		require.Contains(t, string(p[:n]), string(srt[:]))
	})
}

func TestTransportUnparseableQUICPackets(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const rtt = 10 * time.Millisecond
		clientConn, serverConn, closeFn := newSimnetLink(t, rtt)
		defer closeFn()

		var eventRecorder events.Recorder
		tr := &Transport{
			Conn:               serverConn,
			ConnectionIDLength: 10,
			Tracer:             &eventRecorder,
		}
		require.NoError(t, tr.init(true))
		defer tr.Close()

		_, err := clientConn.WriteTo([]byte{0x40 /* set the QUIC bit */, 1, 2, 3}, tr.Conn.LocalAddr())
		require.NoError(t, err)

		time.Sleep(rtt) // so that the packet arrives at the server

		require.Equal(t,
			[]qlogwriter.Event{
				qlog.PacketDropped{
					Raw:     qlog.RawInfo{Length: 4},
					Trigger: qlog.PacketDropHeaderParseError,
				},
			},
			eventRecorder.Events(qlog.PacketDropped{}),
		)
	})
}

func TestTransportListening(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const rtt = 10 * time.Millisecond
		clientConn, serverConn, closeFn := newSimnetLink(t, rtt)
		defer closeFn()

		var eventRecorder events.Recorder
		tr := &Transport{
			Conn:               serverConn,
			ConnectionIDLength: 5,
			Tracer:             &eventRecorder,
		}
		require.NoError(t, tr.init(true))
		defer tr.Close()

		data := wire.ComposeVersionNegotiation([]byte{1, 2, 3, 4, 5}, []byte{6, 7, 8, 9, 10}, []protocol.Version{protocol.Version1})

		_, err := clientConn.WriteTo(data, tr.Conn.LocalAddr())
		require.NoError(t, err)

		time.Sleep(rtt) // so that the packet arrives at the server

		require.Equal(t,
			[]qlogwriter.Event{
				qlog.PacketDropped{
					Raw:     qlog.RawInfo{Length: len(data)},
					Trigger: qlog.PacketDropUnknownConnectionID,
				},
			},
			eventRecorder.Events(qlog.PacketDropped{}),
		)
		eventRecorder.Clear()

		ln, err := tr.Listen(&tls.Config{}, nil)
		require.NoError(t, err)

		_, err = clientConn.WriteTo(data, tr.Conn.LocalAddr())
		require.NoError(t, err)
		time.Sleep(rtt) // so that the packet arrives at the server

		require.Equal(t,
			[]qlogwriter.Event{
				qlog.PacketDropped{
					Header:  qlog.PacketHeader{PacketType: qlog.PacketTypeVersionNegotiation},
					Raw:     qlog.RawInfo{Length: len(data)},
					Trigger: qlog.PacketDropUnexpectedPacket,
				},
			},
			eventRecorder.Events(qlog.PacketDropped{}),
		)

		// only a single listener can be set
		_, err = tr.Listen(&tls.Config{}, nil)
		require.Error(t, err)
		require.ErrorIs(t, err, errListenerAlreadySet)

		require.NoError(t, ln.Close())
		// now it's possible to add a new listener
		ln, err = tr.Listen(&tls.Config{}, nil)
		require.NoError(t, err)
		defer ln.Close()
	})
}

func TestTransportNonQUICPackets(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const rtt = 10 * time.Millisecond
		clientConn, serverConn, closeFn := newSimnetLink(t, rtt)
		defer closeFn()

		tr := &Transport{Conn: serverConn}
		defer tr.Close()

		ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond)
		defer cancel()
		_, _, err := tr.ReadNonQUICPacket(ctx, make([]byte, 1024))
		require.Error(t, err)
		require.ErrorIs(t, err, context.DeadlineExceeded)

		data := []byte{0 /* don't set the QUIC bit */, 1, 2, 3}
		_, err = clientConn.WriteTo(data, tr.Conn.LocalAddr())
		require.NoError(t, err)
		_, err = clientConn.WriteTo(data, tr.Conn.LocalAddr())
		require.NoError(t, err)

		ctx, cancel = context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		b := make([]byte, 1024)
		n, addr, err := tr.ReadNonQUICPacket(ctx, b)
		require.NoError(t, err)
		require.Equal(t, data, b[:n])
		require.Equal(t, addr, clientConn.LocalAddr())

		// now send a lot of packets without reading them
		for i := range 2 * maxQueuedNonQUICPackets {
			data := append([]byte{0 /* don't set the QUIC bit */, uint8(i)}, bytes.Repeat([]byte{uint8(i)}, 1000)...)
			_, err = clientConn.WriteTo(data, tr.Conn.LocalAddr())
			require.NoError(t, err)
		}

		time.Sleep(rtt) // so that all packets arrive at the server

		var received int
		for {
			ctx, cancel = context.WithTimeout(context.Background(), 20*time.Millisecond)
			defer cancel()
			_, _, err := tr.ReadNonQUICPacket(ctx, b)
			if errors.Is(err, context.DeadlineExceeded) {
				break
			}
			require.NoError(t, err)
			received++
		}
		require.Equal(t, received, maxQueuedNonQUICPackets)
	})
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

	synctest.Test(t, func(t *testing.T) {
		_, serverConn, closeFn := newSimnetLink(t, 10*time.Millisecond)
		defer closeFn()

		var conn *connTestHooks
		handshakeChan := make(chan struct{})
		blockRun := make(chan struct{})
		if early {
			conn = &connTestHooks{
				earlyConnReady:    func() <-chan struct{} { return handshakeChan },
				handshakeComplete: func() <-chan struct{} { return make(chan struct{}) },
			}
		} else {
			conn = &connTestHooks{
				handshakeComplete: func() <-chan struct{} { return handshakeChan },
			}
		}
		conn.run = func() error { <-blockRun; return errors.New("done") }
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
			_ qlogwriter.Trace,
			_ utils.Logger,
			_ protocol.Version,
		) *wrappedConn {
			return &wrappedConn{testHooks: conn}
		}

		tr := &Transport{Conn: serverConn}
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

		synctest.Wait()

		select {
		case <-errChan:
			t.Fatal("Dial shouldn't have returned")
		default:
		}

		close(handshakeChan)

		synctest.Wait()

		select {
		case err := <-errChan:
			require.NoError(t, err)
		default:
		}
	})
}

func TestTransportDialingVersionNegotiation(t *testing.T) {
	originalClientConnConstructor := newClientConnection
	t.Cleanup(func() { newClientConnection = originalClientConnConstructor })

	conn := &connTestHooks{
		handshakeComplete: func() <-chan struct{} { return make(chan struct{}) },
		run:               func() error { return &errCloseForRecreating{nextPacketNumber: 109, nextVersion: 789} },
	}
	conn2 := &connTestHooks{
		handshakeComplete: func() <-chan struct{} { return make(chan struct{}) },
		run:               func() error { return assert.AnError },
	}

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
		_ qlogwriter.Trace,
		_ utils.Logger,
		v protocol.Version,
	) *wrappedConn {
		connChan <- connParams{pn: pn, hasNegotiatedVersion: hasNegotiatedVersion, version: v}
		if counter == 0 {
			counter++
			return &wrappedConn{testHooks: conn}
		}
		return &wrappedConn{testHooks: conn2}
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
	synctest.Test(t, func(t *testing.T) {
		clientConn, serverConn, closeFn := newSimnetLink(t, 10*time.Millisecond)
		defer closeFn()

		srk := StatelessResetKey{1, 2, 3, 4}
		tr := &Transport{
			Conn:               serverConn,
			ConnectionIDLength: 4,
			StatelessResetKey:  &srk,
		}
		tr.init(true)
		defer tr.Close()

		var closePacket []byte
		if local {
			closePacket = []byte("foobar")
		}

		const expiry = 50 * time.Millisecond
		handler := &mockPacketHandler{}
		connID := protocol.ParseConnectionID([]byte{4, 3, 2, 1})
		m := (*packetHandlerMap)(tr)
		require.True(t, m.Add(connID, handler))
		m.ReplaceWithClosed([]protocol.ConnectionID{connID}, closePacket, expiry)

		p := make([]byte, 100)
		p[0] = 0x40 // QUIC bit
		copy(p[1:], connID.Bytes())

		var sent atomic.Int64
		errChan := make(chan error, 1)
		stopSending := make(chan struct{})
		go func() {
			defer close(errChan)
			ticker := time.NewTicker(expiry / 200)
			timeout := time.NewTimer(time.Second)
			for {
				select {
				case <-stopSending:
					return
				case <-timeout.C:
					errChan <- errors.New("timeout")
					return
				case <-ticker.C:
				}
				if _, err := clientConn.WriteTo(p, tr.Conn.LocalAddr()); err != nil {
					errChan <- err
					return
				}
				sent.Add(1)
			}
		}()

		// For locally closed connections, CONNECTION_CLOSE packets are sent with an exponential backoff
		var received int
		clientConn.SetReadDeadline(time.Now().Add(time.Hour))
		for {
			b := make([]byte, 100)
			n, _, err := clientConn.ReadFrom(b)
			require.NoError(t, err)
			// at some point, the connection is cleaned up, and we'll receive a stateless reset
			if !bytes.Equal(b[:n], []byte("foobar")) {
				require.GreaterOrEqual(t, n, protocol.MinStatelessResetSize)
				close(stopSending) // stop sending packets
				break
			}
			received++
		}

		select {
		case err := <-errChan:
			require.NoError(t, err)
		case <-time.After(time.Second):
			t.Fatal("timeout")
		}

		numSent := sent.Load()
		if !local {
			require.Zero(t, received)
			t.Logf("sent %d packets", numSent)
			return
		}
		t.Logf("sent %d packets, received %d CONNECTION_CLOSE copies", numSent, received)
		require.Equal(t, int(math.Ceil(math.Log2(float64(numSent)))), received)
	})
}
