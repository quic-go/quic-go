package self_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	quicproxy "github.com/quic-go/quic-go/integrationtests/tools/proxy"

	"github.com/stretchr/testify/require"
)

func TestConnectionMigration(t *testing.T) {
	ln, err := quic.ListenAddr("localhost:0", getTLSConfig(), getQuicConfig(nil))
	require.NoError(t, err)
	defer ln.Close()

	tr1 := &quic.Transport{Conn: newUDPConnLocalhost(t)}
	defer tr1.Close()
	tr2 := &quic.Transport{Conn: newUDPConnLocalhost(t)}
	defer tr2.Close()

	var packetsPath1, packetsPath2 atomic.Int64

	const rtt = 5 * time.Millisecond
	proxy := quicproxy.Proxy{
		Conn:       newUDPConnLocalhost(t),
		ServerAddr: ln.Addr().(*net.UDPAddr),
		DelayPacket: func(dir quicproxy.Direction, from, to net.Addr, _ []byte) time.Duration {
			var port int
			switch dir {
			case quicproxy.DirectionIncoming:
				port = from.(*net.UDPAddr).Port
			case quicproxy.DirectionOutgoing:
				port = to.(*net.UDPAddr).Port
			}
			switch port {
			case tr1.Conn.LocalAddr().(*net.UDPAddr).Port:
				packetsPath1.Add(1)
			case tr2.Conn.LocalAddr().(*net.UDPAddr).Port:
				packetsPath2.Add(1)
			default:
				fmt.Println("address not found", from)
			}
			return rtt / 2
		},
	}
	require.NoError(t, proxy.Start())
	defer proxy.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, err := tr1.Dial(ctx, proxy.LocalAddr(), getTLSClientConfig(), getQuicConfig(nil))
	require.NoError(t, err)
	defer conn.CloseWithError(0, "")

	sconn, err := ln.Accept(ctx)
	require.NoError(t, err)
	defer sconn.CloseWithError(0, "")

	sendAndReceiveFile := func(t *testing.T) {
		t.Helper()
		str, err := conn.OpenUniStream()
		require.NoError(t, err)

		errChan := make(chan error, 1)
		go func() {
			defer close(errChan)
			sstr, err := sconn.AcceptUniStream(ctx)
			if err != nil {
				errChan <- fmt.Errorf("accepting stream: %w", err)
				return
			}
			data, err := io.ReadAll(sstr)
			if err != nil {
				errChan <- fmt.Errorf("reading stream data: %w", err)
				return
			}
			if !bytes.Equal(data, PRData) {
				errChan <- errors.New("unexpected data")
			}
		}()

		_, err = str.Write(PRData)
		require.NoError(t, err)
		require.NoError(t, str.Close())

		select {
		case err := <-errChan:
			require.NoError(t, err)
		case <-time.After(time.Second):
			t.Fatal("timed out waiting for data")
		}
	}

	sendAndReceiveFile(t) // stream 2
	require.NotZero(t, packetsPath1.Load())
	require.Zero(t, packetsPath2.Load())

	// probing the path causes a few packets to be sent on path 2
	path, err := conn.AddPath(tr2)
	require.NoError(t, err)
	require.ErrorIs(t, path.Switch(), quic.ErrPathNotValidated)
	require.NoError(t, path.Probe(ctx))
	require.Less(t, int(packetsPath2.Load()), 5)

	// make sure that no more packets are sent on path 2 before switching to the path
	c2 := packetsPath2.Load()
	sendAndReceiveFile(t) // stream 6
	require.Equal(t, packetsPath2.Load(), c2)

	time.Sleep(3 * rtt) // wait for ACKs

	// now switch and make sure that no packets are sent on path 1
	require.NoError(t, path.Switch())
	sendAndReceiveFile(t) // stream 10
	c1 := packetsPath1.Load()
	require.Equal(t, c1, packetsPath1.Load())
	require.Greater(t, packetsPath2.Load(), c2)
	require.Equal(t, tr2.Conn.LocalAddr(), conn.LocalAddr())

	// switch back to the handshake path
	time.Sleep(3 * rtt) // wait for ACKs
	c1BeforeSwitch := packetsPath1.Load()
	c2BeforeSwitch := packetsPath2.Load()
	path2, err := conn.AddPath(tr1)
	require.NoError(t, err)
	require.NoError(t, path2.Probe(ctx))
	time.Sleep(3 * rtt) // wait for ACKs
	require.NoError(t, path2.Switch())
	sendAndReceiveFile(t) // stream 14
	require.Greater(t, packetsPath1.Load(), c1BeforeSwitch)
	// some path probing might have happened
	require.Less(t, int(packetsPath2.Load()-c2BeforeSwitch), 20)
	require.Equal(t, tr1.Conn.LocalAddr(), conn.LocalAddr())
}
