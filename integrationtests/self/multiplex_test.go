package self_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"runtime"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/exp/rand"

	"github.com/quic-go/quic-go"

	"github.com/stretchr/testify/require"
)

func runMultiplexTestServer(t *testing.T, ln *quic.Listener) {
	t.Helper()
	for {
		conn, err := ln.Accept(context.Background())
		if err != nil {
			return
		}
		str, err := conn.OpenUniStream()
		require.NoError(t, err)
		go func() {
			defer str.Close()
			_, err = str.Write(PRData)
			require.NoError(t, err)
		}()

		t.Cleanup(func() { conn.CloseWithError(0, "") })
	}
}

func dialAndReceiveData(tr *quic.Transport, addr net.Addr) error {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	conn, err := tr.Dial(ctx, addr, getTLSClientConfig(), getQuicConfig(nil))
	if err != nil {
		return fmt.Errorf("error dialing: %w", err)
	}
	str, err := conn.AcceptUniStream(ctx)
	if err != nil {
		return fmt.Errorf("error accepting stream: %w", err)
	}
	data, err := io.ReadAll(str)
	if err != nil {
		return fmt.Errorf("error reading data: %w", err)
	}
	if !bytes.Equal(data, PRData) {
		return fmt.Errorf("data mismatch: got %q, expected %q", data, PRData)
	}
	return nil
}

func TestMultiplexesConnectionsToSameServer(t *testing.T) {
	server, err := quic.Listen(newUPDConnLocalhost(t), getTLSConfig(), getQuicConfig(nil))
	require.NoError(t, err)
	defer server.Close()
	go runMultiplexTestServer(t, server)

	tr := &quic.Transport{Conn: newUPDConnLocalhost(t)}
	addTracer(tr)
	defer tr.Close()

	errChan1 := make(chan error, 1)
	go func() { errChan1 <- dialAndReceiveData(tr, server.Addr()) }()
	errChan2 := make(chan error, 1)
	go func() { errChan2 <- dialAndReceiveData(tr, server.Addr()) }()

	select {
	case err := <-errChan1:
		require.NoError(t, err, "error dialing server 1")
	case <-time.After(5 * time.Second):
		t.Error("timeout waiting for done1 to close")
	}
	select {
	case err := <-errChan2:
		require.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Error("timeout waiting for done2 to close")
	}
}

func TestMultiplexingToDifferentServers(t *testing.T) {
	server1, err := quic.Listen(newUPDConnLocalhost(t), getTLSConfig(), getQuicConfig(nil))
	require.NoError(t, err)
	defer server1.Close()
	go runMultiplexTestServer(t, server1)

	server2, err := quic.Listen(newUPDConnLocalhost(t), getTLSConfig(), getQuicConfig(nil))
	require.NoError(t, err)
	defer server2.Close()
	go runMultiplexTestServer(t, server2)

	tr := &quic.Transport{Conn: newUPDConnLocalhost(t)}
	addTracer(tr)
	defer tr.Close()

	errChan1 := make(chan error, 1)
	go func() { errChan1 <- dialAndReceiveData(tr, server1.Addr()) }()
	errChan2 := make(chan error, 1)
	go func() { errChan2 <- dialAndReceiveData(tr, server2.Addr()) }()

	select {
	case err := <-errChan1:
		require.NoError(t, err, "error dialing server 1")
	case <-time.After(5 * time.Second):
		t.Error("timeout waiting for done1 to close")
	}
	select {
	case err := <-errChan2:
		require.NoError(t, err, "error dialing server 2")
	case <-time.After(5 * time.Second):
		t.Error("timeout waiting for done2 to close")
	}
}

func TestMultiplexingConnectToSelf(t *testing.T) {
	tr := &quic.Transport{Conn: newUPDConnLocalhost(t)}
	addTracer(tr)
	defer tr.Close()

	server, err := tr.Listen(getTLSConfig(), getQuicConfig(nil))
	require.NoError(t, err)
	defer server.Close()
	go runMultiplexTestServer(t, server)

	errChan := make(chan error, 1)
	go func() { errChan <- dialAndReceiveData(tr, server.Addr()) }()

	select {
	case err := <-errChan:
		require.NoError(t, err, "error dialing server")
	case <-time.After(5 * time.Second):
		t.Error("timeout waiting for connection to close")
	}
}

func TestMultiplexingServerAndClientOnSameConn(t *testing.T) {
	if runtime.GOOS == "linux" {
		t.Skip("This test requires setting of iptables rules on Linux, see https://stackoverflow.com/questions/23859164/linux-udp-socket-sendto-operation-not-permitted.")
	}

	tr1 := &quic.Transport{Conn: newUPDConnLocalhost(t)}
	addTracer(tr1)
	defer tr1.Close()
	server1, err := tr1.Listen(getTLSConfig(), getQuicConfig(nil))
	require.NoError(t, err)
	defer server1.Close()

	tr2 := &quic.Transport{Conn: newUPDConnLocalhost(t)}
	addTracer(tr2)
	defer tr2.Close()
	server2, err := tr2.Listen(getTLSConfig(), getQuicConfig(nil))
	require.NoError(t, err)
	defer server2.Close()

	done1 := make(chan struct{})
	go func() {
		defer close(done1)
		dialAndReceiveData(tr2, server1.Addr())
	}()

	done2 := make(chan struct{})
	go func() {
		defer close(done2)
		dialAndReceiveData(tr1, server2.Addr())
	}()

	select {
	case <-done1:
	case <-time.After(5 * time.Second):
		t.Error("timeout waiting for done1 to close")
	}
	select {
	case <-done2:
	case <-time.After(time.Second):
		t.Error("timeout waiting for done2 to close")
	}
}

func TestMultiplexingNonQUICPackets(t *testing.T) {
	tr1 := &quic.Transport{Conn: newUPDConnLocalhost(t)}
	defer tr1.Close()
	addTracer(tr1)

	tr2 := &quic.Transport{Conn: newUPDConnLocalhost(t)}
	defer tr2.Close()
	addTracer(tr2)

	server, err := tr1.Listen(getTLSConfig(), getQuicConfig(nil))
	require.NoError(t, err)
	defer server.Close()

	type nonQUICPacket struct {
		b    []byte
		addr net.Addr
		err  error
	}
	done := make(chan struct{})
	var rcvdPackets []nonQUICPacket
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	// start receiving non-QUIC packets
	go func() {
		defer close(done)
		for {
			b := make([]byte, 1024)
			n, addr, err := tr2.ReadNonQUICPacket(ctx, b)
			if errors.Is(err, context.Canceled) {
				return
			}
			rcvdPackets = append(rcvdPackets, nonQUICPacket{b: b[:n], addr: addr, err: err})
		}
	}()

	// send a non-QUIC packet every 100µs
	const packetLen = 128
	var sentPackets atomic.Int64
	errChan := make(chan error, 1)
	go func() {
		ticker := time.NewTicker(time.Millisecond / 10)
		defer ticker.Stop()

		var wroteFirstPacket bool
		for {
			select {
			case <-ticker.C:
				b := make([]byte, packetLen)
				rand.Read(b[1:]) // keep the first byte set to 0, so it's not classified as a QUIC packet
				_, err := tr1.WriteTo(b, tr2.Conn.LocalAddr())
				// The first sendmsg call on a new UDP socket sometimes errors on Linux.
				// It's not clear why this happens.
				// See https://github.com/golang/go/issues/63322.
				if err != nil && !wroteFirstPacket && runtime.GOOS == "linux" && isPermissionError(err) {
					_, err = tr1.WriteTo(b, tr2.Conn.LocalAddr())
				}
				if err != nil {
					errChan <- err
					return
				}
				sentPackets.Add(1)
				wroteFirstPacket = true
			case <-ctx.Done():
				return
			}
		}
	}()

	conn, err := tr2.Dial(
		context.Background(),
		server.Addr(),
		getTLSClientConfig(),
		getQuicConfig(nil),
	)
	require.NoError(t, err)
	defer conn.CloseWithError(0, "")

	serverConn, err := server.Accept(context.Background())
	require.NoError(t, err)
	serverStr, err := serverConn.OpenUniStream()
	require.NoError(t, err)
	go func() {
		defer serverStr.Close()
		_, _ = serverStr.Write(PRData)
	}()

	str, err := conn.AcceptUniStream(context.Background())
	require.NoError(t, err)
	data, err := io.ReadAll(str)
	require.NoError(t, err)
	require.Equal(t, PRData, data)

	// stop sending non-QUIC packets
	cancel()

	select {
	case err := <-errChan:
		t.Fatalf("error sending non-QUIC packets: %v", err)
	case <-done:
	}

	sent := int(sentPackets.Load())
	require.Greater(t, sent, 10, "not enough non-QUIC packets sent: %d", sent)
	rcvd := len(rcvdPackets)
	minExpected := sent * 4 / 5
	require.GreaterOrEqual(t, rcvd, minExpected, "not enough packets received. got: %d, expected at least: %d", rcvd, minExpected)

	for _, p := range rcvdPackets {
		require.Equal(t, tr1.Conn.LocalAddr(), p.addr, "non-QUIC packet received from wrong address")
		require.Equal(t, packetLen, len(p.b), "non-QUIC packet incorrect length")
		require.NoError(t, p.err, "error receiving non-QUIC packet")
	}
}
