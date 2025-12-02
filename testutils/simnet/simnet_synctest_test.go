package simnet

import (
	"math"
	"net"
	"testing"
	"time"

	"github.com/quic-go/quic-go/internal/synctest"

	"github.com/stretchr/testify/require"
)

func newConn(simnet *Simnet, address *net.UDPAddr, linkSettings NodeBiDiLinkSettings) *SimConn {
	return simnet.NewEndpoint(address, linkSettings)
}

func TestSimpleSimNet(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		router := &Simnet{Router: &PerfectRouter{}}

		const latency = 10 * time.Millisecond
		linkSettings := NodeBiDiLinkSettings{
			Downlink: LinkSettings{},
			Uplink:   LinkSettings{},
			Latency:  latency,
		}

		addressA := net.UDPAddr{
			IP:   net.ParseIP("1.0.0.1"),
			Port: 8000,
		}
		connA := newConn(router, &addressA, linkSettings)
		addressB := net.UDPAddr{
			IP:   net.ParseIP("1.0.0.2"),
			Port: 8000,
		}
		connB := newConn(router, &addressB, linkSettings)

		router.Start()
		defer router.Close()

		start := time.Now()
		connA.WriteTo([]byte("hello"), &addressB)
		buf := make([]byte, 1024)
		n, from, err := connB.ReadFrom(buf)
		require.NoError(t, err)
		require.Equal(t, "hello", string(buf[:n]))
		require.Equal(t, addressA.String(), from.String())
		observedLatency := time.Since(start)

		// Only downlink has latency now (uplink is instant)
		expectedLatency := latency
		percentDiff := math.Abs(float64(observedLatency-expectedLatency) / float64(expectedLatency))
		t.Logf("observed latency: %v, expected latency: %v, percent diff: %v", observedLatency, expectedLatency, percentDiff)
		if percentDiff > 0.30 {
			t.Fatalf("latency is wrong: %v. percent off: %v", observedLatency, percentDiff)
		}
	})
}
