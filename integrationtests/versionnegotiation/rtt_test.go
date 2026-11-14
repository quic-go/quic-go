package versionnegotiation

import (
	"context"
	"testing"
	"testing/synctest"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/internal/protocol"

	"github.com/stretchr/testify/require"
)

const rtt = 400 * time.Millisecond

func expectDurationInRTTs(t *testing.T, startTime time.Time, num int) {
	t.Helper()
	testDuration := time.Since(startTime)
	rtts := float32(testDuration) / float32(rtt)
	require.GreaterOrEqual(t, rtts, float32(num))
	require.Less(t, rtts, float32(num+1))
}

func TestVersionNegotiationFailure(t *testing.T) {
	if len(protocol.SupportedVersions) == 1 {
		t.Fatal("Test requires at least 2 supported versions.")
	}

	synctest.Test(t, func(t *testing.T) {
		clientPacketConn, serverPacketConn, closeFn := newSimnetLink(t, rtt)
		defer closeFn(t)

		serverConfig := &quic.Config{}
		serverConfig.Versions = protocol.SupportedVersions[:1]
		ln, err := quic.Listen(serverPacketConn, getTLSConfig(), serverConfig)
		require.NoError(t, err)
		defer ln.Close()

		startTime := time.Now()
		_, err = quic.Dial(
			context.Background(),
			clientPacketConn,
			serverPacketConn.LocalAddr(),
			getTLSClientConfig(),
			maybeAddQLOGTracer(&quic.Config{Versions: protocol.SupportedVersions[1:2]}),
		)
		require.Error(t, err)
		expectDurationInRTTs(t, startTime, 1)
	})
}
