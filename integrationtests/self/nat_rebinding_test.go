package self_test

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	quicproxy "github.com/quic-go/quic-go/integrationtests/tools/proxy"
	"github.com/quic-go/quic-go/qlog"
	"github.com/quic-go/quic-go/qlogwriter"
	"github.com/quic-go/quic-go/testutils/events"

	"github.com/stretchr/testify/require"
)

func TestNATRebinding(t *testing.T) {
	tr, tracer := newPacketTracer()
	tlsConf := getTLSConfig()
	f, err := os.Create("keylog.txt")
	require.NoError(t, err)
	defer f.Close()
	tlsConf.KeyLogWriter = f
	server, err := quic.Listen(
		newUDPConnLocalhost(t),
		tlsConf,
		getQuicConfig(&quic.Config{
			Tracer: func(ctx context.Context, isClient bool, connID quic.ConnectionID) qlogwriter.Trace { return tracer },
		}),
	)
	require.NoError(t, err)
	defer server.Close()

	newPath := newUDPConnLocalhost(t)
	clientUDPConn := newUDPConnLocalhost(t)

	oldPathRTT := scaleDuration(10 * time.Millisecond)
	newPathRTT := scaleDuration(20 * time.Millisecond)
	proxy := quicproxy.Proxy{
		ServerAddr: server.Addr().(*net.UDPAddr),
		Conn:       newUDPConnLocalhost(t),
	}
	var mx sync.Mutex
	var switchedPath bool
	var dataTransferred int
	proxy.DelayPacket = func(dir quicproxy.Direction, _, _ net.Addr, b []byte) time.Duration {
		mx.Lock()
		defer mx.Unlock()

		if dir == quicproxy.DirectionOutgoing {
			dataTransferred += len(b)
			if dataTransferred > len(PRData)/3 {
				if !switchedPath {
					if err := proxy.SwitchConn(clientUDPConn.LocalAddr().(*net.UDPAddr), newPath); err != nil {
						panic(fmt.Sprintf("failed to switch connection: %s", err))
					}
					switchedPath = true
				}
			}
		}
		if switchedPath {
			return newPathRTT
		}
		return oldPathRTT
	}
	require.NoError(t, proxy.Start())
	defer proxy.Close()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	conn, err := quic.Dial(ctx, clientUDPConn, proxy.LocalAddr(), getTLSClientConfig(), getQuicConfig(nil))
	require.NoError(t, err)

	serverConn, err := server.Accept(ctx)
	require.NoError(t, err)
	defer serverConn.CloseWithError(0, "")

	go func() {
		str, err := serverConn.OpenUniStream()
		require.NoError(t, err)
		go func() {
			defer str.Close()
			_, err = str.Write(PRData)
			require.NoError(t, err)
		}()
	}()

	str, err := conn.AcceptUniStream(ctx)
	require.NoError(t, err)
	str.SetReadDeadline(time.Now().Add(5 * time.Second))
	data, err := io.ReadAll(str)
	require.NoError(t, err)
	require.Equal(t, PRData, data)
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
}

// Probing the new path after a NAT rebinding uses one of the client's connection IDs.
// Unless the server retires the old connection ID when switching to the new path,
// it runs out of connection IDs after a few rebindings, and can't switch paths anymore, see
// https://github.com/quic-go/quic-go/issues/5965.
func TestNATRebindingRepeated(t *testing.T) {
	var serverEvents events.Recorder
	server, err := quic.Listen(
		newUDPConnLocalhost(t),
		getTLSConfig(),
		getQuicConfig(&quic.Config{Tracer: newTracer(&serverEvents)}),
	)
	require.NoError(t, err)
	defer server.Close()

	clientUDPConn := newUDPConnLocalhost(t)
	proxy := quicproxy.Proxy{
		ServerAddr: server.Addr().(*net.UDPAddr),
		Conn:       newUDPConnLocalhost(t),
	}
	require.NoError(t, proxy.Start())
	defer proxy.Close()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	// unlike quic.Dial, the Transport uses non-zero-length connection IDs
	tr := &quic.Transport{Conn: clientUDPConn, ConnectionIDLength: 8}
	defer tr.Close()
	conn, err := tr.Dial(ctx, proxy.LocalAddr(), getTLSClientConfig(), getQuicConfig(nil))
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
	for range 8 {
		require.NoError(t, proxy.SwitchConn(clientUDPConn.LocalAddr().(*net.UDPAddr), newUDPConnLocalhost(t)))
		// The server sends to the old address until it switches to the new path,
		// so receiving the echo means that it switched.
		str, err := conn.OpenStream()
		require.NoError(t, err)
		str.SetDeadline(time.Now().Add(scaleDuration(2 * time.Second)))
		_, err = str.Write([]byte("foobar"))
		require.NoError(t, err)
		require.NoError(t, str.Close())
		data, err := io.ReadAll(str)
		require.NoError(t, err)
		require.Equal(t, []byte("foobar"), data)
	}
	requireConnIDsNotLinkable(t, serverEvents.Events())
}
