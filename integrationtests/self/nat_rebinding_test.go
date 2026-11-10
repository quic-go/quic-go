package self_test

import (
	"context"
	"io"
	"net"
	"testing"
	"testing/synctest"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/qlog"
	"github.com/quic-go/quic-go/qlogwriter"
	"github.com/quic-go/quic-go/testutils/events"
	"github.com/quic-go/quic-go/testutils/simnet"

	"github.com/stretchr/testify/require"
)

func TestNATRebinding(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const oldPathRTT = 10 * time.Millisecond
		const newPathRTT = 20 * time.Millisecond

		clientAddr := &net.UDPAddr{IP: net.ParseIP("1.0.0.1"), Port: 9001}
		serverAddr := &net.UDPAddr{IP: net.ParseIP("1.0.0.2"), Port: 9002}
		oldExternalAddr := &net.UDPAddr{IP: net.ParseIP("1.0.0.3"), Port: 9003}
		newExternalAddr := &net.UDPAddr{IP: net.ParseIP("1.0.0.3"), Port: 9004}

		router := newNATRouter(clientAddr, oldExternalAddr)
		n := &simnet.Simnet{Router: router}
		clientPacketConn := n.NewEndpoint(clientAddr, simnet.NodeBiDiLinkSettings{Latency: oldPathRTT / 2})
		serverPacketConn := n.NewEndpoint(serverAddr, simnet.NodeBiDiLinkSettings{
			LatencyFunc: func(p simnet.Packet) time.Duration {
				if p.From.String() == newExternalAddr.String() {
					return newPathRTT - oldPathRTT/2
				}
				return oldPathRTT / 2
			},
		})
		defer n.Close()
		defer clientPacketConn.Close()
		defer serverPacketConn.Close()

		tr, tracer := newPacketTracer()
		server, err := quic.Listen(
			serverPacketConn,
			getTLSConfig(),
			getQuicConfig(&quic.Config{
				Tracer: func(ctx context.Context, isClient bool, connID quic.ConnectionID) qlogwriter.Trace { return tracer },
			}),
		)
		require.NoError(t, err)
		defer server.Close()

		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		conn, err := quic.Dial(ctx, clientPacketConn, serverAddr, getTLSClientConfig(), getQuicConfig(nil))
		require.NoError(t, err)

		serverConn, err := server.Accept(ctx)
		require.NoError(t, err)
		defer serverConn.CloseWithError(0, "")

		go func() {
			str, err := serverConn.OpenUniStream()
			require.NoError(t, err)
			defer str.Close()
			_, err = str.Write(PRData)
			require.NoError(t, err)
		}()

		str, err := conn.AcceptUniStream(ctx)
		require.NoError(t, err)
		str.SetReadDeadline(time.Now().Add(5 * time.Second))
		data := make([]byte, len(PRData)/3)
		_, err = io.ReadFull(str, data)
		require.NoError(t, err)
		router.Rebind(newExternalAddr)
		rest, err := io.ReadAll(str)
		require.NoError(t, err)
		require.Equal(t, PRData, append(data, rest...))
		conn.CloseWithError(0, "")

		// check that a PATH_CHALLENGE was sent
		var pathChallenges [][8]byte
		for _, p := range tr.getSentShortHeaderPackets() {
			for _, f := range p.frames {
				switch fr := f.Frame.(type) {
				case *qlog.PathChallengeFrame:
					pathChallenges = append(pathChallenges, fr.Data)
				}
			}
		}
		require.NotEmpty(t, pathChallenges)

		// check that a PATH_RESPONSE with the correct data was received
		var foundPathResponse bool
		for _, p := range tr.getRcvdShortHeaderPackets() {
			for _, f := range p.frames {
				switch fr := f.Frame.(type) {
				case *qlog.PathResponseFrame:
					require.Contains(t, pathChallenges, fr.Data)
					foundPathResponse = true
				}
			}
		}
		require.True(t, foundPathResponse)
	})
}

// Probing the new path after a NAT rebinding uses one of the client's connection IDs.
// Unless the server retires the old connection ID when switching to the new path,
// it runs out of connection IDs after a few rebindings, and can't switch paths anymore, see
// https://github.com/quic-go/quic-go/issues/5965.
func TestNATRebindingRepeated(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		router := newNATRouter(
			&net.UDPAddr{IP: net.ParseIP("1.0.0.1"), Port: 9001},
			&net.UDPAddr{IP: net.ParseIP("1.0.0.3"), Port: 9003},
		)
		clientPacketConn, serverPacketConn, closeFn := newSimnetLinkWithRouter(t, 10*time.Millisecond, router)
		defer closeFn(t)

		var serverEvents events.Recorder
		server, err := quic.Listen(
			serverPacketConn,
			getTLSConfig(),
			getQuicConfig(&quic.Config{Tracer: newTracer(&serverEvents)}),
		)
		require.NoError(t, err)
		defer server.Close()

		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		// unlike quic.Dial, the Transport uses non-zero-length connection IDs
		tr := &quic.Transport{Conn: clientPacketConn, ConnectionIDLength: 8}
		defer tr.Close()
		conn, err := tr.Dial(ctx, serverPacketConn.LocalAddr(), getTLSClientConfig(), getQuicConfig(nil))
		require.NoError(t, err)
		defer conn.CloseWithError(0, "")
		sconn, err := server.Accept(ctx)
		require.NoError(t, err)
		defer sconn.CloseWithError(0, "")
		go func() {
			for {
				str, err := sconn.AcceptStream(context.Background())
				if err != nil {
					return
				}
				go func() {
					defer str.Close()
					io.Copy(str, str)
				}()
			}
		}()

		// rebind more often than the client provides connection IDs at any given time
		for i := range 8 {
			router.Rebind(&net.UDPAddr{IP: net.ParseIP("1.0.0.3"), Port: 9004 + i})
			// The server sends to the old address until it switches to the new path,
			// so receiving the echo means that it switched.
			str, err := conn.OpenStream()
			require.NoError(t, err)
			str.SetDeadline(time.Now().Add(2 * time.Second))
			_, err = str.Write([]byte("foobar"))
			require.NoError(t, err)
			require.NoError(t, str.Close())
			data, err := io.ReadAll(str)
			require.NoError(t, err)
			require.Equal(t, []byte("foobar"), data)
		}
		requireConnIDsNotLinkable(t, serverEvents.Events())
	})
}
