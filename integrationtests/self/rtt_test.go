package self_test

import (
	"context"
	"errors"
	"io"
	"math/rand/v2"
	"net"
	"testing"
	"testing/synctest"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/qlogwriter"
	"github.com/quic-go/quic-go/testutils/simnet"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func runServerForRTTTest(t *testing.T, serverConn net.PacketConn) <-chan *quic.Conn {
	t.Helper()

	ln, err := quic.Listen(serverConn, getTLSConfig(), getQuicConfig(nil))
	require.NoError(t, err)
	t.Cleanup(func() { ln.Close() })

	connChan := make(chan *quic.Conn, 1)
	go func() {
		for {
			conn, err := ln.Accept(context.Background())
			if err != nil {
				if !errors.Is(err, net.ErrClosed) {
					t.Logf("accept error: %v", err)
				}
				return
			}
			connChan <- conn
			str, err := conn.OpenStream()
			if err != nil {
				t.Logf("open stream error: %v", err)
				return
			}
			if _, err := str.Write(PRData); err != nil {
				t.Logf("write error: %v", err)
				return
			}
			str.Close()
		}
	}()

	return connChan
}

func TestDownloadWithFixedRTT(t *testing.T) {
	for _, rtt := range []time.Duration{
		10 * time.Millisecond,
		100 * time.Millisecond,
		500 * time.Millisecond,
	} {
		t.Run(rtt.String(), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				clientConn, serverConn, closeFn := newSimnetLink(t, rtt)
				defer closeFn(t)

				sconnChan := runServerForRTTTest(t, serverConn)

				ctx, cancel := context.WithTimeout(context.Background(), time.Hour)
				defer cancel()
				conn, err := quic.Dial(
					ctx,
					clientConn,
					serverConn.LocalAddr(),
					getTLSClientConfig(),
					getQuicConfig(nil),
				)
				require.NoError(t, err)
				defer conn.CloseWithError(0, "")

				str, err := conn.AcceptStream(ctx)
				require.NoError(t, err)
				data, err := io.ReadAll(str)
				require.NoError(t, err)
				require.Equal(t, PRData, data)

				sconn := <-sconnChan
				defer sconn.CloseWithError(0, "")

				checkRTTs := func(stats quic.ConnectionStats) {
					t.Helper()
					require.GreaterOrEqual(t, stats.SmoothedRTT, rtt)
					require.GreaterOrEqual(t, stats.MinRTT, rtt)
					require.LessOrEqual(t, stats.SmoothedRTT, rtt+time.Millisecond)
					require.LessOrEqual(t, stats.MinRTT, rtt+time.Millisecond)
				}
				checkRTTs(conn.ConnectionStats())
				checkRTTs(sconn.ConnectionStats())
			})
		})
	}
}

func TestDownloadWithReordering(t *testing.T) {
	for _, rtt := range []time.Duration{
		5 * time.Millisecond,
		50 * time.Millisecond,
		250 * time.Millisecond,
	} {
		t.Run(rtt.String(), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				counter, tracer := newPacketTracer()

				n := &simnet.Simnet{Router: &simnet.PerfectRouter{}}
				settings := simnet.NodeBiDiLinkSettings{
					LatencyFunc: func(simnet.Packet) time.Duration {
						min := rtt * 9 / 10
						max := rtt * 11 / 10
						return (min + time.Duration(rand.IntN(int(max-min)))) / 2
					},
				}
				clientConn := n.NewEndpoint(&net.UDPAddr{IP: net.ParseIP("1.0.0.1"), Port: 9001}, settings)
				serverConn := n.NewEndpoint(&net.UDPAddr{IP: net.ParseIP("1.0.0.2"), Port: 9002}, settings)
				require.NoError(t, n.Start())
				defer func() {
					require.NoError(t, clientConn.Close())
					require.NoError(t, serverConn.Close())
					require.NoError(t, n.Close())
				}()

				sconnChan := runServerForRTTTest(t, serverConn)

				ctx, cancel := context.WithTimeout(context.Background(), time.Hour)
				defer cancel()
				conn, err := quic.Dial(
					ctx,
					clientConn,
					serverConn.LocalAddr(),
					getTLSClientConfig(),
					getQuicConfig(&quic.Config{
						Tracer: func(context.Context, bool, quic.ConnectionID) qlogwriter.Trace { return tracer },
					}),
				)
				require.NoError(t, err)
				defer conn.CloseWithError(0, "")

				str, err := conn.AcceptStream(ctx)
				require.NoError(t, err)
				data, err := io.ReadAll(str)
				require.NoError(t, err)
				require.Equal(t, PRData, data)

				sconn := <-sconnChan
				defer sconn.CloseWithError(0, "")

				packets := counter.getRcvdShortHeaderPackets()
				var packetNumbers []protocol.PacketNumber
				for _, p := range packets {
					packetNumbers = append(packetNumbers, p.hdr.PacketNumber)
				}

				// Count reorderings: a reordering occurs when we receive a packet
				// with a number lower than the highest number we've seen so far
				var reorderings int
				var highestSeen protocol.PacketNumber
				for _, pn := range packetNumbers {
					if pn < highestSeen {
						reorderings++
					}
					if pn > highestSeen {
						highestSeen = pn
					}
				}

				t.Logf("Smoothed RTT: %s", conn.ConnectionStats().SmoothedRTT)
				assert.GreaterOrEqual(t, conn.ConnectionStats().SmoothedRTT, rtt*9/10)
				assert.LessOrEqual(t, conn.ConnectionStats().SmoothedRTT, rtt*11/10)
				t.Logf("received %d short header packets, detected %d reorderings", len(packetNumbers), reorderings)
				assert.GreaterOrEqual(t, reorderings, 20, "expected at least 20 reorderings")
			})
		})
	}
}
