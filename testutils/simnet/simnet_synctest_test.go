//go:build goexperiment.synctest

package simnet

import (
	"fmt"
	"math"
	"net"
	"testing"
	"time"

	"testing/synctest"

	"github.com/marcopolo/simnet/internal/require"
)

const oneMbps = 1_000_000

func newConn(simnet *Simnet, address *net.UDPAddr, linkSettings NodeBiDiLinkSettings) *SimConn {
	return simnet.NewEndpoint(address, linkSettings)
}

func TestSimpleSimNet_synctest(t *testing.T) {
	synctest.Run(func() {
		router := &Simnet{}

		const bandwidth = 10 * oneMbps
		const latency = 10 * time.Millisecond
		linkSettings := NodeBiDiLinkSettings{
			Downlink: LinkSettings{
				BitsPerSecond: bandwidth,
				Latency:       latency / 2,
			},
			Uplink: LinkSettings{
				BitsPerSecond: bandwidth,
				Latency:       latency / 2,
			},
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

		expectedLatency := latency
		percentDiff := math.Abs(float64(observedLatency-expectedLatency) / float64(expectedLatency))
		t.Logf("observed latency: %v, expected latency: %v, percent diff: %v", observedLatency, expectedLatency, percentDiff)
		if percentDiff > 0.30 {
			t.Fatalf("latency is wrong: %v. percent off: %v", observedLatency, percentDiff)
		}
	})
}

func TestSimNetBandwidth_synctest(t *testing.T) {
	synctest.Run(func() {
		router := &Simnet{}

		const bandwidth = 40 * oneMbps
		const latency = 10 * time.Millisecond
		const MTU = 1200
		linkSettings := NodeBiDiLinkSettings{
			Downlink: LinkSettings{
				BitsPerSecond: bandwidth,
				MTU:           MTU,
				Latency:       latency / 2,
			},
			Uplink: LinkSettings{
				BitsPerSecond: bandwidth,
				MTU:           MTU,
				Latency:       latency / 2,
			},
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

		err := router.Start()
		require.NoError(t, err)
		defer router.Close()

		readDone := make(chan struct{})

		bytesRead := 0

		start := time.Now()
		var observedLatency time.Duration
		var readDuration time.Duration
		go func() {
			defer close(readDone)
			buf := make([]byte, MTU)
			var startReadTime time.Time
			for {
				n, _, err := connB.ReadFrom(buf)
				if observedLatency == 0 {
					startReadTime = time.Now()
					observedLatency = time.Since(start)
				}
				bytesRead += n
				if err != nil {
					readDuration = time.Since(startReadTime)
					return
				}
			}
		}()

		totalBytes := 10 << 20
		bytesSent := 0
		chunk := make([]byte, MTU)
		for bytesSent < totalBytes {
			time.Sleep(100 * time.Microsecond)
			connA.WriteTo(chunk, &addressB)
			bytesSent += len(chunk)
		}

		connB.Close()

		<-readDone
		expectedLatency := latency
		percentDiff := math.Abs(float64(observedLatency-expectedLatency) / float64(expectedLatency))
		t.Logf("observed latency: %v, expected latency: %v, percent diff: %v", observedLatency, expectedLatency, percentDiff)
		if percentDiff > 0.30 {
			t.Fatalf("latency is wrong: %v. percent off: %v", observedLatency, percentDiff)
		}

		observedBandwidth := float64(bytesRead*8) / readDuration.Seconds()
		expectedBandwidth := float64(bandwidth)
		fmt.Println("sent bytes", bytesSent)
		fmt.Println("Read bytes", bytesRead)
		percentDiffBandwidth := math.Abs(observedBandwidth-expectedBandwidth) / expectedBandwidth
		t.Logf("observed bandwidth: %v mbps, expected bandwidth: %v mbps, percent diff: %v", observedBandwidth/oneMbps, expectedBandwidth/oneMbps, percentDiffBandwidth)
		if percentDiffBandwidth > 0.20 {
			t.Fatalf("bandwidth is wrong: %v. percent off: %v", observedBandwidth, percentDiffBandwidth)
		}
	})
}
