package versionnegotiation

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	quicproxy "github.com/quic-go/quic-go/integrationtests/tools/proxy"
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

	serverConfig := &quic.Config{}
	serverConfig.Versions = protocol.SupportedVersions[:1]
	ln, err := quic.ListenAddr("localhost:0", getTLSConfig(), serverConfig)
	require.NoError(t, err)
	defer ln.Close()

	proxyConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	require.NoError(t, err)
	defer proxyConn.Close()
	// start the proxy
	proxy := quicproxy.Proxy{
		Conn:        proxyConn,
		ServerAddr:  ln.Addr().(*net.UDPAddr),
		DelayPacket: func(quicproxy.Direction, []byte) time.Duration { return rtt / 2 },
	}
	require.NoError(t, proxy.Start())
	defer proxy.Close()

	startTime := time.Now()
	_, err = quic.DialAddr(
		context.Background(),
		proxy.LocalAddr().String(),
		getTLSClientConfig(),
		maybeAddQLOGTracer(&quic.Config{Versions: protocol.SupportedVersions[1:2]}),
	)
	require.Error(t, err)
	expectDurationInRTTs(t, startTime, 1)
}
