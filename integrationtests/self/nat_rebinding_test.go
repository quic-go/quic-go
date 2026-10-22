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

// TestNATRebindingRepeatedly rebinds the client many times on one connection. The client uses
// non-zero-length connection IDs, so the server needs one of the client's connection IDs for every
// new path. It must retire the connection IDs it no longer uses, so that the client issues new ones.
func TestNATRebindingRepeatedly(t *testing.T) {
	server, err := quic.Listen(newUDPConnLocalhost(t), getTLSConfig(), getQuicConfig(nil))
	require.NoError(t, err)
	defer server.Close()

	proxy := quicproxy.Proxy{ServerAddr: server.Addr().(*net.UDPAddr), Conn: newUDPConnLocalhost(t)}
	require.NoError(t, proxy.Start())
	defer proxy.Close()

	clientUDPConn := newUDPConnLocalhost(t)
	tr := &quic.Transport{Conn: clientUDPConn, ConnectionIDLength: 8}
	defer tr.Close()
	ctx, cancel := context.WithTimeout(context.Background(), scaleDuration(10*time.Second))
	defer cancel()
	conn, err := tr.Dial(ctx, proxy.LocalAddr(), getTLSClientConfig(), getQuicConfig(nil))
	require.NoError(t, err)
	defer conn.CloseWithError(0, "")

	serverConn, err := server.Accept(ctx)
	require.NoError(t, err)
	defer serverConn.CloseWithError(0, "")
	go func() {
		for {
			str, err := serverConn.AcceptStream(context.Background())
			if err != nil {
				return
			}
			go func() {
				defer str.Close()
				io.Copy(str, str)
			}()
		}
	}()

	for i := range 10 {
		if i > 0 {
			require.NoError(t, proxy.SwitchConn(clientUDPConn.LocalAddr().(*net.UDPAddr), newUDPConnLocalhost(t)))
		}
		str, err := conn.OpenStreamSync(ctx)
		require.NoError(t, err)
		msg := fmt.Appendf(nil, "after rebinding %d", i)
		_, err = str.Write(msg)
		require.NoError(t, err)
		require.NoError(t, str.Close())
		str.SetReadDeadline(time.Now().Add(scaleDuration(2 * time.Second)))
		data, err := io.ReadAll(str)
		require.NoError(t, err, "no response on the new path after rebinding %d", i)
		require.Equal(t, msg, data)
	}
}
