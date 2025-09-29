package versionnegotiation

import (
	"context"
	"errors"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/qlog"
	"github.com/quic-go/quic-go/qlogwriter"
	"github.com/quic-go/quic-go/testutils/events"

	"github.com/stretchr/testify/require"
)

func TestServerSupportsMoreVersionsThanClient(t *testing.T) {
	supportedVersions := append([]quic.Version{}, protocol.SupportedVersions...)
	protocol.SupportedVersions = append(protocol.SupportedVersions, []protocol.Version{7, 8, 9, 10}...)
	defer func() { protocol.SupportedVersions = supportedVersions }()

	var serverEventTracer events.Recorder
	serverConfig := &quic.Config{
		Versions: []protocol.Version{7, 8, protocol.SupportedVersions[0], 9},
		Tracer: func(context.Context, bool, quic.ConnectionID) qlogwriter.Trace {
			return &events.Trace{Recorder: &serverEventTracer}
		},
	}
	server, err := quic.ListenAddr("localhost:0", getTLSConfig(), serverConfig)
	require.NoError(t, err)
	defer server.Close()

	var clientEventTracer events.Recorder
	conn, err := quic.DialAddr(
		context.Background(),
		fmt.Sprintf("localhost:%d", server.Addr().(*net.UDPAddr).Port),
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
}

func TestClientSupportsMoreVersionsThanServer(t *testing.T) {
	supportedVersions := append([]quic.Version{}, protocol.SupportedVersions...)
	protocol.SupportedVersions = append(protocol.SupportedVersions, []protocol.Version{7, 8, 9, 10}...)
	defer func() { protocol.SupportedVersions = supportedVersions }()

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
	server, err := quic.ListenAddr("localhost:0", getTLSConfig(), serverConfig)
	require.NoError(t, err)
	defer server.Close()

	clientVersions := []protocol.Version{7, 8, 9, protocol.SupportedVersions[0], 10}
	var clientEventTracer events.Recorder
	conn, err := quic.DialAddr(
		context.Background(),
		fmt.Sprintf("localhost:%d", server.Addr().(*net.UDPAddr).Port),
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
	require.NoError(t, conn.CloseWithError(0, ""))

	select {
	case <-sconn.Context().Done():
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
}

func TestServerDisablesVersionNegotiation(t *testing.T) {
	// The server doesn't support the highest supported version, which is the first one the client will try,
	// but it supports a bunch of versions that the client doesn't speak
	var serverEventTracer events.Recorder
	serverConfig := &quic.Config{
		Versions: []protocol.Version{quic.Version1},
		Tracer: func(context.Context, bool, quic.ConnectionID) qlogwriter.Trace {
			return &events.Trace{Recorder: &serverEventTracer}
		},
	}
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	tr := &quic.Transport{
		Conn:                             conn,
		DisableVersionNegotiationPackets: true,
	}
	ln, err := tr.Listen(getTLSConfig(), serverConfig)
	require.NoError(t, err)
	defer ln.Close()

	var clientEventTracer events.Recorder
	_, err = quic.DialAddr(
		context.Background(),
		fmt.Sprintf("localhost:%d", conn.LocalAddr().(*net.UDPAddr).Port),
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
	var nerr net.Error
	require.True(t, errors.As(err, &nerr))
	require.True(t, nerr.Timeout())
	require.Empty(t, clientEventTracer.Events(qlog.VersionNegotiationReceived{}))
}
