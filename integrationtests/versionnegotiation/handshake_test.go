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
	"github.com/quic-go/quic-go/logging"

	"github.com/stretchr/testify/require"
)

type result struct {
	loggedVersions                 bool
	receivedVersionNegotiation     bool
	chosen                         logging.Version
	clientVersions, serverVersions []logging.Version
}

func newVersionNegotiationTracer(t *testing.T) (*result, *logging.ConnectionTracer) {
	r := &result{}
	return r, &logging.ConnectionTracer{
		NegotiatedVersion: func(chosen logging.Version, clientVersions, serverVersions []logging.Version) {
			if r.loggedVersions {
				t.Fatal("only expected one call to NegotiatedVersions")
			}
			r.loggedVersions = true
			r.chosen = chosen
			r.clientVersions = clientVersions
			r.serverVersions = serverVersions
		},
		ReceivedVersionNegotiationPacket: func(dest, src logging.ArbitraryLenConnectionID, _ []logging.Version) {
			r.receivedVersionNegotiation = true
		},
	}
}

func TestServerSupportsMoreVersionsThanClient(t *testing.T) {
	supportedVersions := append([]quic.Version{}, protocol.SupportedVersions...)
	protocol.SupportedVersions = append(protocol.SupportedVersions, []protocol.Version{7, 8, 9, 10}...)
	defer func() { protocol.SupportedVersions = supportedVersions }()

	expectedVersion := protocol.SupportedVersions[0]
	serverConfig := &quic.Config{}
	serverConfig.Versions = []protocol.Version{7, 8, protocol.SupportedVersions[0], 9}
	serverResult, serverTracer := newVersionNegotiationTracer(t)
	serverConfig.Tracer = func(context.Context, logging.Perspective, quic.ConnectionID) *logging.ConnectionTracer {
		return serverTracer
	}
	server, err := quic.ListenAddr("localhost:0", getTLSConfig(), serverConfig)
	require.NoError(t, err)
	defer server.Close()

	clientResult, clientTracer := newVersionNegotiationTracer(t)
	conn, err := quic.DialAddr(
		context.Background(),
		fmt.Sprintf("localhost:%d", server.Addr().(*net.UDPAddr).Port),
		getTLSClientConfig(),
		maybeAddQLOGTracer(&quic.Config{Tracer: func(ctx context.Context, perspective logging.Perspective, id quic.ConnectionID) *logging.ConnectionTracer {
			return clientTracer
		}}),
	)
	require.NoError(t, err)

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

	require.Equal(t, expectedVersion, clientResult.chosen)
	require.False(t, clientResult.receivedVersionNegotiation)
	require.Equal(t, protocol.SupportedVersions, clientResult.clientVersions)
	require.Empty(t, clientResult.serverVersions)
	require.Equal(t, expectedVersion, serverResult.chosen)
	require.Equal(t, serverConfig.Versions, serverResult.serverVersions)
	require.Empty(t, serverResult.clientVersions)
}

func TestClientSupportsMoreVersionsThanServer(t *testing.T) {
	supportedVersions := append([]quic.Version{}, protocol.SupportedVersions...)
	protocol.SupportedVersions = append(protocol.SupportedVersions, []protocol.Version{7, 8, 9, 10}...)
	defer func() { protocol.SupportedVersions = supportedVersions }()

	expectedVersion := protocol.SupportedVersions[0]
	// The server doesn't support the highest supported version, which is the first one the client will try,
	// but it supports a bunch of versions that the client doesn't speak
	serverResult, serverTracer := newVersionNegotiationTracer(t)
	serverConfig := &quic.Config{}
	serverConfig.Versions = supportedVersions
	serverConfig.Tracer = func(context.Context, logging.Perspective, quic.ConnectionID) *logging.ConnectionTracer {
		return serverTracer
	}
	server, err := quic.ListenAddr("localhost:0", getTLSConfig(), serverConfig)
	require.NoError(t, err)
	defer server.Close()

	clientVersions := []protocol.Version{7, 8, 9, protocol.SupportedVersions[0], 10}
	clientResult, clientTracer := newVersionNegotiationTracer(t)
	conn, err := quic.DialAddr(
		context.Background(),
		fmt.Sprintf("localhost:%d", server.Addr().(*net.UDPAddr).Port),
		getTLSClientConfig(),
		maybeAddQLOGTracer(&quic.Config{
			Versions: clientVersions,
			Tracer: func(context.Context, logging.Perspective, quic.ConnectionID) *logging.ConnectionTracer {
				return clientTracer
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

	require.Equal(t, expectedVersion, clientResult.chosen)
	require.True(t, clientResult.receivedVersionNegotiation)
	require.Equal(t, clientVersions, clientResult.clientVersions)
	require.Subset(t, clientResult.serverVersions, supportedVersions) // may contain greased versions
	require.Equal(t, expectedVersion, serverResult.chosen)
	require.Equal(t, serverConfig.Versions, serverResult.serverVersions)
	require.Empty(t, serverResult.clientVersions)
}

func TestServerDisablesVersionNegotiation(t *testing.T) {
	// The server doesn't support the highest supported version, which is the first one the client will try,
	// but it supports a bunch of versions that the client doesn't speak
	_, serverTracer := newVersionNegotiationTracer(t)
	serverConfig := &quic.Config{Versions: []protocol.Version{quic.Version1}}
	serverConfig.Tracer = func(context.Context, logging.Perspective, quic.ConnectionID) *logging.ConnectionTracer {
		return serverTracer
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

	clientVersions := []protocol.Version{quic.Version2}
	clientResult, clientTracer := newVersionNegotiationTracer(t)
	_, err = quic.DialAddr(
		context.Background(),
		fmt.Sprintf("localhost:%d", conn.LocalAddr().(*net.UDPAddr).Port),
		getTLSClientConfig(),
		maybeAddQLOGTracer(&quic.Config{
			Versions: clientVersions,
			Tracer: func(context.Context, logging.Perspective, quic.ConnectionID) *logging.ConnectionTracer {
				return clientTracer
			},
			HandshakeIdleTimeout: 100 * time.Millisecond,
		}),
	)
	require.Error(t, err)
	var nerr net.Error
	require.True(t, errors.As(err, &nerr))
	require.True(t, nerr.Timeout())
	require.False(t, clientResult.receivedVersionNegotiation)
}
