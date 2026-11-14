package versionnegotiation

import (
	"context"
	"errors"
	"net"
	"testing"
	"testing/synctest"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/qlog"
	"github.com/quic-go/quic-go/qlogwriter"
	"github.com/quic-go/quic-go/testutils/events"

	"github.com/stretchr/testify/require"
)

func TestServerSupportsMoreVersionsThanClient(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		supportedVersions := append([]quic.Version{}, protocol.SupportedVersions...)
		protocol.SupportedVersions = append(protocol.SupportedVersions, []protocol.Version{7, 8, 9, 10}...)
		defer func() { protocol.SupportedVersions = supportedVersions }()

		clientPacketConn, serverPacketConn, closeFn := newSimnetLink(t, 10*time.Millisecond)
		defer closeFn(t)

		var serverEventTracer events.Recorder
		serverConfig := &quic.Config{
			Versions: []protocol.Version{7, 8, protocol.SupportedVersions[0], 9},
			Tracer: func(context.Context, bool, quic.ConnectionID) qlogwriter.Trace {
				return &events.Trace{Recorder: &serverEventTracer}
			},
		}
		server, err := quic.Listen(serverPacketConn, getTLSConfig(), serverConfig)
		require.NoError(t, err)
		defer server.Close()

		var clientEventTracer events.Recorder
		conn, err := quic.Dial(
			context.Background(),
			clientPacketConn,
			serverPacketConn.LocalAddr(),
			getTLSClientConfig(),
			maybeAddQLOGTracer(&quic.Config{Tracer: func(context.Context, bool, quic.ConnectionID) qlogwriter.Trace {
				return &events.Trace{Recorder: &clientEventTracer}
			}}),
		)
		require.NoError(t, err)

		expectedVersion := protocol.SupportedVersions[0]
		sconn, err := server.Accept(context.Background())
		require.NoError(t, err)
		require.Equal(t, expectedVersion, sconn.ConnectionState().Version)

		require.Equal(t, expectedVersion, conn.ConnectionState().Version)
		require.NoError(t, conn.CloseWithError(0, ""))

		select {
		case <-sconn.Context().Done():
			// Expected behavior
		case <-time.After(5 * time.Second):
			t.Fatal("Timeout waiting for connection to close")
		}

		require.Empty(t, clientEventTracer.Events(qlog.VersionNegotiationReceived{}))
		require.Equal(t,
			[]qlogwriter.Event{
				qlog.VersionInformation{
					ClientVersions: protocol.SupportedVersions,
					ChosenVersion:  expectedVersion,
				},
			},
			clientEventTracer.Events(qlog.VersionInformation{}),
		)
		require.Equal(t,
			[]qlogwriter.Event{
				qlog.VersionInformation{
					ServerVersions: serverConfig.Versions,
					ChosenVersion:  expectedVersion,
				},
			},
			serverEventTracer.Events(qlog.VersionInformation{}),
		)
	})
}

func TestClientSupportsMoreVersionsThanServer(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		supportedVersions := append([]quic.Version{}, protocol.SupportedVersions...)
		protocol.SupportedVersions = append(protocol.SupportedVersions, []protocol.Version{7, 8, 9, 10}...)
		defer func() { protocol.SupportedVersions = supportedVersions }()

		clientPacketConn, serverPacketConn, closeFn := newSimnetLink(t, 10*time.Millisecond)
		defer closeFn(t)

		expectedVersion := protocol.SupportedVersions[0]
		// The server doesn't support the highest supported version, which is the first one the client will try,
		// but it supports a bunch of versions that the client doesn't speak
		var serverEventTracer events.Recorder
		serverConfig := &quic.Config{
			Versions: supportedVersions,
			Tracer: func(context.Context, bool, quic.ConnectionID) qlogwriter.Trace {
				return &events.Trace{Recorder: &serverEventTracer}
			},
		}
		server, err := quic.Listen(serverPacketConn, getTLSConfig(), serverConfig)
		require.NoError(t, err)
		defer server.Close()

		clientVersions := []protocol.Version{7, 8, 9, protocol.SupportedVersions[0], 10}
		var clientEventTracer events.Recorder
		conn, err := quic.Dial(
			context.Background(),
			clientPacketConn,
			serverPacketConn.LocalAddr(),
			getTLSClientConfig(),
			maybeAddQLOGTracer(&quic.Config{
				Versions: clientVersions,
				Tracer: func(context.Context, bool, quic.ConnectionID) qlogwriter.Trace {
					return &events.Trace{Recorder: &clientEventTracer}
				},
			}),
		)
		require.NoError(t, err)

		sconn, err := server.Accept(context.Background())
		require.NoError(t, err)
		require.Equal(t, expectedVersion, sconn.ConnectionState().Version)

		require.Equal(t, protocol.SupportedVersions[0], conn.ConnectionState().Version)
		// the client must still receive packets after 3 PTOs of the old connection
		time.Sleep(time.Second)
		require.NoError(t, sconn.CloseWithError(0, ""))

		select {
		case <-conn.Context().Done():
			// Expected behavior
		case <-time.After(5 * time.Second):
			t.Fatal("Timeout waiting for connection to close")
		}

		require.Len(t, clientEventTracer.Events(qlog.VersionNegotiationReceived{}), 1)
		supportedVersionInclGreased := clientEventTracer.Events(qlog.VersionNegotiationReceived{})[0].(qlog.VersionNegotiationReceived).SupportedVersions
		require.Equal(t,
			[]qlogwriter.Event{
				qlog.VersionInformation{
					ClientVersions: clientVersions,
					ServerVersions: supportedVersionInclGreased,
					ChosenVersion:  expectedVersion,
				},
			},
			clientEventTracer.Events(qlog.VersionInformation{}),
		)
		require.Equal(t,
			[]qlogwriter.Event{
				qlog.VersionInformation{
					ServerVersions: supportedVersions,
					ChosenVersion:  expectedVersion,
				},
			},
			serverEventTracer.Events(qlog.VersionInformation{}),
		)
	})
}

func TestServerDisablesVersionNegotiation(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		clientPacketConn, serverPacketConn, closeFn := newSimnetLink(t, 10*time.Millisecond)
		defer closeFn(t)

		// The server doesn't support the highest supported version, which is the first one the client will try,
		// but it supports a bunch of versions that the client doesn't speak
		var serverEventTracer events.Recorder
		serverConfig := &quic.Config{
			Versions: []protocol.Version{quic.Version1},
			Tracer: func(context.Context, bool, quic.ConnectionID) qlogwriter.Trace {
				return &events.Trace{Recorder: &serverEventTracer}
			},
		}
		tr := &quic.Transport{
			Conn:                             serverPacketConn,
			DisableVersionNegotiationPackets: true,
		}
		defer tr.Close()
		ln, err := tr.Listen(getTLSConfig(), serverConfig)
		require.NoError(t, err)
		defer ln.Close()

		var clientEventTracer events.Recorder
		_, err = quic.Dial(
			context.Background(),
			clientPacketConn,
			serverPacketConn.LocalAddr(),
			getTLSClientConfig(),
			maybeAddQLOGTracer(&quic.Config{
				Versions: []protocol.Version{quic.Version2},
				Tracer: func(context.Context, bool, quic.ConnectionID) qlogwriter.Trace {
					return &events.Trace{Recorder: &clientEventTracer}
				},
				HandshakeIdleTimeout: 100 * time.Millisecond,
			}),
		)
		require.Error(t, err)
		nerr, ok := errors.AsType[net.Error](err)
		require.True(t, ok)
		require.True(t, nerr.Timeout())
		require.Empty(t, clientEventTracer.Events(qlog.VersionNegotiationReceived{}))
	})
}
