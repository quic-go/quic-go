package self_test

import (
	"io"
	"net"
	"testing"
	"testing/synctest"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/testutils/simnet"

	"github.com/stretchr/testify/require"
)

func newStreamPriorityTestConnections(t *testing.T) (client, server *quic.Conn) {
	t.Helper()

	const (
		rtt               = 10 * time.Millisecond
		bandwidthBytesSec = 1 << 20
	)
	n := &simnet.Simnet{Router: &simnet.PerfectRouter{}}
	linkSettings := func() simnet.NodeBiDiLinkSettings {
		var nextTransmission time.Time
		return simnet.NodeBiDiLinkSettings{
			LatencyFunc: func(p simnet.Packet) time.Duration {
				now := time.Now()
				if nextTransmission.Before(now) {
					nextTransmission = now
				}
				nextTransmission = nextTransmission.Add(time.Duration(len(p.Data)) * time.Second / bandwidthBytesSec)
				return nextTransmission.Add(rtt / 2).Sub(now)
			},
		}
	}
	clientPacketConn := n.NewEndpoint(&net.UDPAddr{IP: net.ParseIP("1.0.0.1"), Port: 9001}, linkSettings())
	serverPacketConn := n.NewEndpoint(&net.UDPAddr{IP: net.ParseIP("1.0.0.2"), Port: 9002}, linkSettings())
	require.NoError(t, n.Start())
	t.Cleanup(func() {
		require.NoError(t, clientPacketConn.Close())
		require.NoError(t, serverPacketConn.Close())
		require.NoError(t, n.Close())
	})

	serverConfig := getQuicConfig(&quic.Config{
		InitialStreamReceiveWindow:     uint64(len(PRData)),
		InitialConnectionReceiveWindow: uint64(len(PRData)),
		DisablePathMTUDiscovery:        true,
	})
	listener, err := quic.Listen(
		serverPacketConn,
		getTLSConfig(),
		serverConfig,
	)
	require.NoError(t, err)
	t.Cleanup(func() { listener.Close() })

	client, err = quic.Dial(
		t.Context(),
		clientPacketConn,
		serverPacketConn.LocalAddr(),
		getTLSClientConfig(),
		getQuicConfig(&quic.Config{DisablePathMTUDiscovery: true}),
	)
	require.NoError(t, err)
	t.Cleanup(func() { client.CloseWithError(0, "") })
	server, err = listener.Accept(t.Context())
	require.NoError(t, err)
	t.Cleanup(func() { server.CloseWithError(0, "") })
	return client, server
}

type streamPriorityTestCase struct {
	name        string
	incremental bool
	urgencies   [4]int8
	sizes       [4]int
	order       [4]int
}

var streamPriorityTests = [...]streamPriorityTestCase{
	{
		name:        "incremental streams use urgency and round robin",
		incremental: true,
		urgencies:   [4]int8{0, 0, 1, 1},
		sizes:       [4]int{len(PRData) / 2, len(PRData) / 4, len(PRData) / 8, len(PRData) / 16},
		// Round robin makes the smaller stream at each urgency finish first,
		// while both urgency 0 streams finish before either urgency 1 stream.
		order: [4]int{1, 0, 3, 2},
	},
	{
		name:        "non-incremental streams use stream ID",
		incremental: false,
		urgencies:   [4]int8{3, 3, 3, 3},
		sizes:       [4]int{len(PRData) / 2, len(PRData) / 4, len(PRData) / 8, len(PRData) / 16},
		order:       [4]int{0, 1, 2, 3},
	},
}

func TestStreamPriority(t *testing.T) {
	for _, test := range streamPriorityTests {
		t.Run(test.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				client, server := newStreamPriorityTestConnections(t)

				var streams [4]*quic.SendStream
				for i := range streams {
					str, err := client.OpenUniStreamSync(t.Context())
					require.NoError(t, err)
					str.SetPriority(test.urgencies[i], test.incremental)
					_, err = str.Write([]byte{0}) // make the stream visible to the peer
					require.NoError(t, err)
					streams[i] = str
				}

				type readResult struct {
					id  quic.StreamID
					n   int64
					err error
				}
				completed := make(chan readResult, len(streams))
				for range streams {
					str, err := server.AcceptUniStream(t.Context())
					require.NoError(t, err)
					go func() {
						n, err := io.Copy(io.Discard, str)
						completed <- readResult{id: str.StreamID(), n: n, err: err}
					}()
				}

				writeErrs := make(chan error, len(streams))
				for i, str := range streams {
					go func() {
						_, err := str.Write(PRData[:test.sizes[i]])
						if err == nil {
							err = str.Close()
						}
						writeErrs <- err
					}()
				}

				for _, i := range test.order {
					result := <-completed
					require.NoError(t, result.err)
					require.Equal(t, streams[i].StreamID(), result.id)
					require.EqualValues(t, test.sizes[i]+1, result.n)
				}
				for range streams {
					require.NoError(t, <-writeErrs)
				}
			})
		})
	}
}
