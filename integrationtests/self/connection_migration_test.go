package self_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
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

func TestConnectionMigrationRepeated(t *testing.T) {
	const connIDLen = 8
	const numMigrations = 6 // needs to be larger than the connection ID limit (2 with a limit of 4)

	serverTr := &quic.Transport{Conn: newUDPConnLocalhost(t), ConnectionIDLength: connIDLen}
	defer serverTr.Close()
	ln, err := serverTr.Listen(getTLSConfig(), getQuicConfig(nil))
	require.NoError(t, err)
	defer ln.Close()

	// Record the DCIDs of short header packets sent by the client.
	// Since the client switches to the connection ID used for probing when it switches paths,
	// we expect to see a new connection ID after every migration.
	var mx sync.Mutex
	dcids := make(map[string]struct{})

	const rtt = 5 * time.Millisecond
	proxy := quicproxy.Proxy{
		Conn:       newUDPConnLocalhost(t),
		ServerAddr: ln.Addr().(*net.UDPAddr),
		DelayPacket: func(dir quicproxy.Direction, _, _ net.Addr, b []byte) time.Duration {
			if dir == quicproxy.DirectionIncoming && len(b) > connIDLen && b[0]&0x80 == 0 {
				mx.Lock()
				dcids[string(b[1:1+connIDLen])] = struct{}{}
				mx.Unlock()
			}
			return rtt / 2
		},
	}
	require.NoError(t, proxy.Start())
	defer proxy.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	tr := &quic.Transport{Conn: newUDPConnLocalhost(t)}
	defer tr.Close()
	conn, err := tr.Dial(ctx, proxy.LocalAddr(), getTLSClientConfig(), getQuicConfig(nil))
	require.NoError(t, err)
	defer conn.CloseWithError(0, "")

	sconn, err := ln.Accept(ctx)
	require.NoError(t, err)
	defer sconn.CloseWithError(0, "")

	sendAndReceive := func(t *testing.T) {
		t.Helper()
		str, err := conn.OpenUniStream()
		require.NoError(t, err)
		_, err = str.Write(PRDataLong[:2048])
		require.NoError(t, err)
		require.NoError(t, str.Close())

		sstr, err := sconn.AcceptUniStream(ctx)
		require.NoError(t, err)
		data, err := io.ReadAll(sstr)
		require.NoError(t, err)
		require.Equal(t, PRDataLong[:2048], data)
	}

	sendAndReceive(t)

	// Repeatedly migrate the connection to a new path.
	// This used to fail after 2 migrations, since connection IDs were never retired:
	// the pool of available connection IDs (4, in this implementation) was exhausted,
	// and path probing stalled without sending any packets.
	for i := range numMigrations {
		newTr := &quic.Transport{Conn: newUDPConnLocalhost(t)}
		defer newTr.Close()
		path, err := conn.AddPath(newTr)
		require.NoError(t, err)

		probeCtx, probeCancel := context.WithTimeout(ctx, 5*time.Second)
		require.NoErrorf(t, path.Probe(probeCtx), "probing failed on migration %d", i+1)
		probeCancel()
		require.NoError(t, path.Switch())

		sendAndReceive(t)
		require.Equal(t, newTr.Conn.LocalAddr(), conn.LocalAddr())
		time.Sleep(3 * rtt) // wait for ACKs, and for the server to issue new connection IDs
	}

	// The client uses a new connection ID on every path:
	// the handshake connection ID, and one per migration.
	// Additional rotations (e.g. right after handshake completion) might have happened as well.
	mx.Lock()
	defer mx.Unlock()
	require.GreaterOrEqual(t, len(dcids), numMigrations+1)
}
