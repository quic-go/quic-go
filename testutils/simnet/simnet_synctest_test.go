package simnet

import (
	"net"
	"testing"
	"testing/synctest"
	"time"

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
		t.Logf("observed latency: %v, expected latency: %v", observedLatency, latency)
		require.InEpsilon(t, latency, observedLatency, 0.30)
	})
}
