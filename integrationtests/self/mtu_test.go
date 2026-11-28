package self_test

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/qlog"
	"github.com/quic-go/quic-go/testutils/events"
	"github.com/quic-go/quic-go/testutils/simnet"

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
	synctest.Test(t, func(t *testing.T) {
		const rtt = 5 * time.Millisecond
		const mtu = 1400

		var mx sync.Mutex
		var maxPacketSizeServer int
		var clientPacketSizes []int
		clientAddr := &net.UDPAddr{IP: net.ParseIP("1.0.0.1"), Port: 9001}
		serverAddr := &net.UDPAddr{IP: net.ParseIP("1.0.0.2"), Port: 9002}
		n := &simnet.Simnet{
			Router: &callbackRouter{
				Router: &simnet.PerfectRouter{},
				OnSendPacket: func(p simnet.Packet) {
					mx.Lock()
					defer mx.Unlock()
					if p.To.String() == serverAddr.String() {
						clientPacketSizes = append(clientPacketSizes, len(p.Data))
					} else {
						maxPacketSizeServer = max(maxPacketSizeServer, len(p.Data))
					}
				},
			},
		}
		// the link drops packets larger than the MTU before they reach the router
		settings := simnet.NodeBiDiLinkSettings{Latency: rtt / 2, Uplink: simnet.LinkSettings{MTU: mtu}}
		clientPacketConn := n.NewEndpoint(clientAddr, settings)
		defer clientPacketConn.Close()
		serverPacketConn := n.NewEndpoint(serverAddr, settings)
		defer serverPacketConn.Close()
		defer n.Close()

		ln, err := quic.Listen(
			serverPacketConn,
			getTLSConfig(),
			getQuicConfig(&quic.Config{
				InitialPacketSize:       1234,
				DisablePathMTUDiscovery: true,
				EnableDatagrams:         true,
			}),
		)
		require.NoError(t, err)
		defer ln.Close()

		var eventRecorder events.Recorder
		conn, err := quic.Dial(
			context.Background(),
			clientPacketConn,
			serverAddr,
			getTLSClientConfig(),
			getQuicConfig(&quic.Config{
				InitialPacketSize: protocol.MinInitialPacketSize,
				EnableDatagrams:   true,
				Tracer:            newTracer(&eventRecorder),
			}),
		)
		require.NoError(t, err)
		defer conn.CloseWithError(0, "")

		serverConn, err := ln.Accept(context.Background())
		require.NoError(t, err)
		defer serverConn.CloseWithError(0, "")

		serverErrChan := make(chan error, 1)
		go func() {
			str, err := serverConn.AcceptStream(context.Background())
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

		err = conn.SendDatagram(make([]byte, 2000))
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
		require.NotEmpty(t, eventRecorder.Events(qlog.MTUUpdated{}))

		var mtus []int
		for _, ev := range eventRecorder.Events(qlog.MTUUpdated{}) {
			mtus = append(mtus, ev.(qlog.MTUUpdated).Value)
		}

		var numProbes int
		for _, ev := range eventRecorder.Events(qlog.PacketSent{}) {
			if ev.(qlog.PacketSent).IsMTUProbePacket {
				numProbes++
			}
		}
		require.NotZero(t, numProbes)

		maxPacketSizeClient := mtus[len(mtus)-1]
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
	})
}

func TestMaxUDPPayloadSizeTransportParameter(t *testing.T) {
	const (
		serverMaxUDPPayloadSize = 1232
		clientMaxUDPPayloadSize = 1300
	)

	server := &quic.Transport{Conn: newUDPConnLocalhost(t), MaxUDPPayloadSize: serverMaxUDPPayloadSize}
	defer server.Close()
	ln, err := server.Listen(getTLSConfig(), getQuicConfig(nil))
	require.NoError(t, err)
	defer ln.Close()

	client := &quic.Transport{Conn: newUDPConnLocalhost(t), MaxUDPPayloadSize: clientMaxUDPPayloadSize}
	defer client.Close()
	var eventRecorder events.Recorder
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := client.Dial(ctx, ln.Addr(), getTLSClientConfig(), getQuicConfig(&quic.Config{
		// the Initial packet needs to fit into the server's max_udp_payload_size
		InitialPacketSize: protocol.MinInitialPacketSize,
		Tracer:            newTracer(&eventRecorder),
	}))
	require.NoError(t, err)
	defer conn.CloseWithError(0, "")

	var sent, received []protocol.ByteCount
	for _, ev := range eventRecorder.Events(qlog.ParametersSet{}) {
		e := ev.(qlog.ParametersSet)
		switch e.Initiator {
		case qlog.InitiatorLocal:
			sent = append(sent, e.MaxUDPPayloadSize)
		case qlog.InitiatorRemote:
			received = append(received, e.MaxUDPPayloadSize)
		}
	}
	require.Equal(t, []protocol.ByteCount{clientMaxUDPPayloadSize}, sent)
	require.Equal(t, []protocol.ByteCount{serverMaxUDPPayloadSize}, received)
}

func TestMaxUDPPayloadSizeEnforcement(t *testing.T) {
	const maxUDPPayloadSize = 1232

	server := &quic.Transport{Conn: newUDPConnLocalhost(t), MaxUDPPayloadSize: maxUDPPayloadSize}
	defer server.Close()
	ln, err := server.Listen(getTLSConfig(), getQuicConfig(nil))
	require.NoError(t, err)
	defer ln.Close()

	dial := func(t *testing.T, initialPacketSize uint16) (*quic.Conn, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return quic.Dial(ctx, newUDPConnLocalhost(t), ln.Addr(), getTLSClientConfig(), getQuicConfig(&quic.Config{
			InitialPacketSize:    initialPacketSize,
			HandshakeIdleTimeout: scaleDuration(100 * time.Millisecond),
		}))
	}

	t.Run("at the limit", func(t *testing.T) {
		conn, err := dial(t, maxUDPPayloadSize)
		require.NoError(t, err)
		conn.CloseWithError(0, "")
	})

	// The server drops the client's Initial packets, since they exceed the limit.
	t.Run("above the limit", func(t *testing.T) {
		_, err := dial(t, maxUDPPayloadSize+1)
		var idleTimeoutErr *quic.IdleTimeoutError
		require.ErrorAs(t, err, &idleTimeoutErr)
	})
}
