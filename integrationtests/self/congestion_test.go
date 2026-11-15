package self_test

import (
	"context"
	"io"
	"net"
	"testing"
	"testing/synctest"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/testutils/simnet"

	"github.com/stretchr/testify/require"
)

func TestCongestionControl(t *testing.T) {
	const (
		bandwidth = 10_000_000 // bits per second
		rtt       = 40 * time.Millisecond
	)
	throughputECN, statsECN := measureBulkTransfer(t, bandwidth, rtt, true)
	throughputNoECN, statsNoECN := measureBulkTransfer(t, bandwidth, rtt, false)
	t.Logf("with ECN: %.2f Mbit/s, %d packets lost, smoothed RTT %s",
		throughputECN/1e6, statsECN.PacketsLost, statsECN.SmoothedRTT)
	t.Logf("without ECN: %.2f Mbit/s, %d packets lost, smoothed RTT %s",
		throughputNoECN/1e6, statsNoECN.PacketsLost, statsNoECN.SmoothedRTT)

	require.Greater(t, throughputECN, 0.9*bandwidth)
	require.Less(t, throughputECN, 1.1*bandwidth)
	require.Greater(t, throughputNoECN, 0.9*bandwidth)
	require.Less(t, throughputNoECN, 1.1*bandwidth)
	// After slow start, the congestion window grows by one packet per RTT,
	// too slowly to overflow the queue during this transfer.
	// Ignoring CE marks therefore shows up as queuing delay, not as packet loss.
	require.GreaterOrEqual(t, statsECN.SmoothedRTT, rtt)
	require.Less(t, statsECN.SmoothedRTT, rtt+20*time.Millisecond)
	require.GreaterOrEqual(t, statsNoECN.SmoothedRTT, rtt)
	require.Less(t, statsNoECN.SmoothedRTT, rtt+20*time.Millisecond)
	// with ECN, the CoDel queue marks packets instead of dropping them
	require.Less(t, 10*statsECN.PacketsLost, statsNoECN.PacketsLost)
}

// measureBulkTransfer sends 10 MB over a link with the given bandwidth and a CoDel queue.
// It returns the throughput in bits per second, and the sender's connection stats.
func measureBulkTransfer(t *testing.T, bandwidth int, rtt time.Duration, ecn bool) (throughput float64, stats quic.ConnectionStats) {
	const size = 10 << 20

	synctest.Test(t, func(t *testing.T) {
		var router simnet.Router = &simnet.PerfectRouter{}
		if !ecn {
			// The path clears the ECN codepoint, so ECN validation fails, and the sender stops using ECN.
			router = &remarkingRouter{
				Remark: func(protocol.ECN) protocol.ECN { return protocol.ECNNon },
			}
		}
		n := &simnet.Simnet{Router: router}
		defer n.Close()
		clientConn := n.NewEndpoint(
			&net.UDPAddr{IP: net.ParseIP("1.0.0.1"), Port: 9001},
			simnet.NodeBiDiLinkSettings{
				Latency: rtt / 2,
				Uplink:  simnet.LinkSettings{Bandwidth: bandwidth},
			},
		)
		defer clientConn.Close()
		serverConn := n.NewEndpoint(
			&net.UDPAddr{IP: net.ParseIP("1.0.0.2"), Port: 9002},
			simnet.NodeBiDiLinkSettings{Latency: rtt / 2},
		)
		defer serverConn.Close()

		ln, err := quic.Listen(serverConn, getTLSConfig(), getQuicConfig(nil))
		require.NoError(t, err)
		defer ln.Close()

		conn, err := quic.Dial(context.Background(), clientConn, ln.Addr(), getTLSClientConfig(), getQuicConfig(nil))
		require.NoError(t, err)
		defer conn.CloseWithError(0, "")
		sconn, err := ln.Accept(context.Background())
		require.NoError(t, err)

		start := time.Now()
		errChan := make(chan error, 1)
		go func() {
			str, err := conn.OpenUniStream()
			if err != nil {
				errChan <- err
				return
			}
			if _, err := str.Write(make([]byte, size)); err != nil {
				errChan <- err
				return
			}
			errChan <- str.Close()
		}()
		str, err := sconn.AcceptUniStream(context.Background())
		require.NoError(t, err)
		received, err := io.Copy(io.Discard, str)
		require.NoError(t, err)
		require.Equal(t, int64(size), received)
		require.NoError(t, <-errChan)

		throughput = float64(size*8) / time.Since(start).Seconds()
		stats = conn.ConnectionStats()
	})
	return throughput, stats
}
