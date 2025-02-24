package self_test

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	quicproxy "github.com/quic-go/quic-go/integrationtests/tools/proxy"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/logging"

	"github.com/stretchr/testify/require"
)

func TestInitialPacketSize(t *testing.T) {
	server := newUDPConnLocalhost(t)
	client := newUDPConnLocalhost(t)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		defer close(done)
		quic.Dial(ctx, client, server.LocalAddr(), getTLSClientConfig(), getQuicConfig(&quic.Config{
			InitialPacketSize: 1337,
		}))
	}()

	buf := make([]byte, 2000)
	n, _, err := server.ReadFrom(buf)
	require.NoError(t, err)
	require.Equal(t, 1337, n)

	cancel()
	<-done
}

func TestPathMTUDiscovery(t *testing.T) {
	rtt := scaleDuration(5 * time.Millisecond)
	const mtu = 1400

	ln, err := quic.Listen(
		newUDPConnLocalhost(t),
		getTLSConfig(),
		getQuicConfig(&quic.Config{
			InitialPacketSize:       1234,
			DisablePathMTUDiscovery: true,
			EnableDatagrams:         true,
		}),
	)
	require.NoError(t, err)
	defer ln.Close()

	serverErrChan := make(chan error, 1)
	go func() {
		conn, err := ln.Accept(context.Background())
		if err != nil {
			serverErrChan <- err
			return
		}
		str, err := conn.AcceptStream(context.Background())
		if err != nil {
			serverErrChan <- err
			return
		}
		defer str.Close()
		if _, err := io.Copy(str, str); err != nil {
			serverErrChan <- err
			return
		}
	}()

	var mx sync.Mutex
	var maxPacketSizeServer int
	var clientPacketSizes []int
	proxy := &quicproxy.Proxy{
		Conn:        newUDPConnLocalhost(t),
		ServerAddr:  ln.Addr().(*net.UDPAddr),
		DelayPacket: func(quicproxy.Direction, net.Addr, net.Addr, []byte) time.Duration { return rtt / 2 },
		DropPacket: func(dir quicproxy.Direction, _, _ net.Addr, packet []byte) bool {
			if len(packet) > mtu {
				return true
			}
			mx.Lock()
			defer mx.Unlock()
			switch dir {
			case quicproxy.DirectionIncoming:
				clientPacketSizes = append(clientPacketSizes, len(packet))
			case quicproxy.DirectionOutgoing:
				if len(packet) > maxPacketSizeServer {
					maxPacketSizeServer = len(packet)
				}
			}
			return false
		},
	}
	require.NoError(t, proxy.Start())
	defer proxy.Close()

	// Make sure to use v4-only socket here.
	// We can't reliably set the DF bit on dual-stack sockets on older versions of macOS (before Sequoia).
	tr := &quic.Transport{Conn: newUDPConnLocalhost(t)}
	defer tr.Close()

	var mtus []logging.ByteCount
	conn, err := tr.Dial(
		context.Background(),
		proxy.LocalAddr(),
		getTLSClientConfig(),
		getQuicConfig(&quic.Config{
			InitialPacketSize: protocol.MinInitialPacketSize,
			EnableDatagrams:   true,
			Tracer: func(context.Context, logging.Perspective, quic.ConnectionID) *logging.ConnectionTracer {
				return &logging.ConnectionTracer{
					UpdatedMTU: func(mtu logging.ByteCount, _ bool) { mtus = append(mtus, mtu) },
				}
			},
		}),
	)
	require.NoError(t, err)
	defer conn.CloseWithError(0, "")

	err = conn.SendDatagram(make([]byte, 2000))
	require.Error(t, err)
	var datagramErr *quic.DatagramTooLargeError
	require.ErrorAs(t, err, &datagramErr)
	initialMaxDatagramSize := datagramErr.MaxDatagramPayloadSize

	str, err := conn.OpenStream()
	require.NoError(t, err)

	clientErrChan := make(chan error, 1)
	go func() {
		data, err := io.ReadAll(str)
		if err != nil {
			clientErrChan <- err
			return
		}
		if !bytes.Equal(data, PRDataLong) {
			clientErrChan <- fmt.Errorf("echoed data doesn't match: %x", data)
			return
		}
		clientErrChan <- nil
	}()

	_, err = str.Write(PRDataLong)
	require.NoError(t, err)
	str.Close()

	select {
	case err := <-clientErrChan:
		require.NoError(t, err)
	case err := <-serverErrChan:
		t.Fatalf("server error: %v", err)
	case <-time.After(20 * time.Second):
		t.Fatal("timeout")
	}

	err = conn.SendDatagram(make([]byte, 2000))
	require.Error(t, err)
	require.ErrorAs(t, err, &datagramErr)
	finalMaxDatagramSize := datagramErr.MaxDatagramPayloadSize

	mx.Lock()
	defer mx.Unlock()
	require.NotEmpty(t, mtus)

	maxPacketSizeClient := int(mtus[len(mtus)-1])
	t.Logf("max client packet size: %d, MTU: %d", maxPacketSizeClient, mtu)
	t.Logf("max datagram size: initial: %d, final: %d", initialMaxDatagramSize, finalMaxDatagramSize)
	t.Logf("max server packet size: %d, MTU: %d", maxPacketSizeServer, mtu)

	require.GreaterOrEqual(t, maxPacketSizeClient, mtu-25)
	const maxDiff = 40 // this includes the 21 bytes for the short header, 16 bytes for the encryption tag, and framing overhead
	require.GreaterOrEqual(t, int(initialMaxDatagramSize), protocol.MinInitialPacketSize-maxDiff)
	require.GreaterOrEqual(t, int(finalMaxDatagramSize), maxPacketSizeClient-maxDiff)
	// MTU discovery was disabled on the server side
	require.Equal(t, 1234, maxPacketSizeServer)

	var numPacketsLargerThanDiscoveredMTU int
	for _, s := range clientPacketSizes {
		if s > maxPacketSizeClient {
			numPacketsLargerThanDiscoveredMTU++
		}
	}
	// The client shouldn't have sent any packets larger than the MTU it discovered,
	// except for at most one MTU probe packet.
	require.LessOrEqual(t, numPacketsLargerThanDiscoveredMTU, 1)
}
