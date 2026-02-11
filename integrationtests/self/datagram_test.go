package self_test

import (
	"bytes"
	"context"
	mrand "math/rand/v2"
	"net"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/internal/wire"
	"github.com/quic-go/quic-go/testutils/simnet"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDatagramNegotiation(t *testing.T) {
	t.Run("server enable, client enable", func(t *testing.T) {
		testDatagramNegotiation(t, true, true)
	})
	t.Run("server enable, client disable", func(t *testing.T) {
		testDatagramNegotiation(t, true, false)
	})
	t.Run("server disable, client enable", func(t *testing.T) {
		testDatagramNegotiation(t, false, true)
	})
	t.Run("server disable, client disable", func(t *testing.T) {
		testDatagramNegotiation(t, false, false)
	})
}

func testDatagramNegotiation(t *testing.T, serverEnableDatagram, clientEnableDatagram bool) {
	server, err := quic.Listen(
		newUDPConnLocalhost(t),
		getTLSConfig(),
		getQuicConfig(&quic.Config{EnableDatagrams: serverEnableDatagram}),
	)
	require.NoError(t, err)
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	clientConn, err := quic.Dial(
		ctx,
		newUDPConnLocalhost(t),
		server.Addr(),
		getTLSClientConfig(),
		getQuicConfig(&quic.Config{EnableDatagrams: clientEnableDatagram}),
	)
	require.NoError(t, err)
	defer clientConn.CloseWithError(0, "")

	serverConn, err := server.Accept(ctx)
	require.NoError(t, err)
	defer serverConn.CloseWithError(0, "")

	serverState := serverConn.ConnectionState().SupportsDatagrams
	clientState := clientConn.ConnectionState().SupportsDatagrams
	require.Equal(t, serverEnableDatagram, serverState.Local, "server local datagram support")
	require.Equal(t, clientEnableDatagram, serverState.Remote, "server view of client datagram support")
	require.Equal(t, clientEnableDatagram, clientState.Local, "client local datagram support")
	require.Equal(t, serverEnableDatagram, clientState.Remote, "client view of server datagram support")

	if clientEnableDatagram {
		require.NoError(t, serverConn.SendDatagram([]byte("foo")))
		datagram, err := clientConn.ReceiveDatagram(ctx)
		require.NoError(t, err)
		require.Equal(t, []byte("foo"), datagram)
	} else {
		require.Error(t, serverConn.SendDatagram([]byte("foo")))
	}

	if serverEnableDatagram {
		require.NoError(t, clientConn.SendDatagram([]byte("bar")))
		datagram, err := serverConn.ReceiveDatagram(ctx)
		require.NoError(t, err)
		require.Equal(t, []byte("bar"), datagram)
	} else {
		require.Error(t, clientConn.SendDatagram([]byte("bar")))
	}
}

func TestDatagramSizeLimit(t *testing.T) {
	const maxDatagramSize = 456
	originalMaxDatagramSize := wire.MaxDatagramSize
	wire.MaxDatagramSize = maxDatagramSize
	t.Cleanup(func() { wire.MaxDatagramSize = originalMaxDatagramSize })

	server, err := quic.Listen(
		newUDPConnLocalhost(t),
		getTLSConfig(),
		getQuicConfig(&quic.Config{EnableDatagrams: true}),
	)
	require.NoError(t, err)
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	clientConn, err := quic.Dial(
		ctx,
		newUDPConnLocalhost(t),
		server.Addr(),
		getTLSClientConfig(),
		getQuicConfig(&quic.Config{EnableDatagrams: true}),
	)
	require.NoError(t, err)
	defer clientConn.CloseWithError(0, "")

	err = clientConn.SendDatagram(bytes.Repeat([]byte("a"), maxDatagramSize+100)) // definitely too large
	require.Error(t, err)
	var sizeErr *quic.DatagramTooLargeError
	require.ErrorAs(t, err, &sizeErr)
	require.InDelta(t, sizeErr.MaxDatagramPayloadSize, maxDatagramSize, 10)

	require.NoError(t, clientConn.SendDatagram(bytes.Repeat([]byte("b"), int(sizeErr.MaxDatagramPayloadSize))))
	require.Error(t, clientConn.SendDatagram(bytes.Repeat([]byte("c"), int(sizeErr.MaxDatagramPayloadSize+1))))

	serverConn, err := server.Accept(ctx)
	require.NoError(t, err)
	defer serverConn.CloseWithError(0, "")
	datagram, err := serverConn.ReceiveDatagram(ctx)
	require.NoError(t, err)
	require.Equal(t, bytes.Repeat([]byte("b"), int(sizeErr.MaxDatagramPayloadSize)), datagram)
}

func TestDatagramLoss(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const rtt = 100 * time.Millisecond
		const numDatagrams = 100
		const datagramSize = 500

		clientAddr := &net.UDPAddr{IP: net.ParseIP("1.0.0.1"), Port: 9001}
		serverAddr := &net.UDPAddr{IP: net.ParseIP("1.0.0.2"), Port: 9002}
		var droppedToClient, droppedToServer, total atomic.Int32
		n := &simnet.Simnet{
			Router: &directionAwareDroppingRouter{
				ClientAddr: clientAddr,
				ServerAddr: serverAddr,
				Drop: func(d direction, p simnet.Packet) bool {
					if wire.IsLongHeaderPacket(p.Data[0]) { // don't drop Long Header packets
						return false
					}
					if len(p.Data) < datagramSize { // don't drop ACK-only packets
						return false
					}
					total.Add(1)
					// drop about 20% of Short Header packets with DATAGRAM frames
					if mrand.Int()%5 == 0 {
						switch d {
						case directionToClient:
							droppedToClient.Add(1)
						case directionToServer:
							droppedToServer.Add(1)
						}
						return true
					}
					return false
				},
			},
		}
		settings := simnet.NodeBiDiLinkSettings{Latency: rtt / 2}
		clientPacketConn := n.NewEndpoint(clientAddr, settings)
		defer clientPacketConn.Close()
		serverPacketConn := n.NewEndpoint(serverAddr, settings)
		defer serverPacketConn.Close()
		require.NoError(t, n.Start())
		defer n.Close()

		server, err := quic.Listen(
			serverPacketConn,
			getTLSConfig(),
			getQuicConfig(&quic.Config{DisablePathMTUDiscovery: true, EnableDatagrams: true}),
		)
		require.NoError(t, err)
		defer server.Close()

		const sendInterval = time.Second // send a datagram every second
		ctx, cancel := context.WithTimeout(context.Background(), (numDatagrams+10)*sendInterval)
		defer cancel()
		clientConn, err := quic.Dial(
			ctx,
			clientPacketConn,
			serverPacketConn.LocalAddr(),
			getTLSClientConfig(),
			getQuicConfig(&quic.Config{DisablePathMTUDiscovery: true, EnableDatagrams: true}),
		)
		require.NoError(t, err)
		defer clientConn.CloseWithError(0, "")

		serverConn, err := server.Accept(ctx)
		require.NoError(t, err)
		defer serverConn.CloseWithError(0, "")

		var clientDatagrams, serverDatagrams int
		clientErrChan := make(chan error, 1)
		go func() {
			defer close(clientErrChan)
			for {
				if _, err := clientConn.ReceiveDatagram(ctx); err != nil {
					clientErrChan <- err
					return
				}
				clientDatagrams++
			}
		}()

		for i := range numDatagrams {
			payload := bytes.Repeat([]byte{uint8(i)}, datagramSize)
			require.NoError(t, clientConn.SendDatagram(payload))
			require.NoError(t, serverConn.SendDatagram(payload))
			time.Sleep(sendInterval)
		}

		serverErrChan := make(chan error, 1)
		go func() {
			defer close(serverErrChan)
			for {
				if _, err := serverConn.ReceiveDatagram(ctx); err != nil {
					serverErrChan <- err
					return
				}
				serverDatagrams++
			}
		}()

		select {
		case err := <-clientErrChan:
			require.ErrorIs(t, err, context.DeadlineExceeded)
		case <-time.After(5 * numDatagrams * sendInterval):
			t.Fatal("timeout")
		}
		select {
		case err := <-serverErrChan:
			require.ErrorIs(t, err, context.DeadlineExceeded)
		case <-time.After(5 * numDatagrams * sendInterval):
			t.Fatal("timeout")
		}

		numDroppedToClient := droppedToClient.Load()
		numDroppedToServer := droppedToServer.Load()
		t.Logf("dropped %d to client and %d to server out of %d packets", numDroppedToClient, numDroppedToServer, total.Load())
		assert.NotZero(t, numDroppedToClient)
		assert.NotZero(t, numDroppedToServer)
		t.Logf("server received %d out of %d sent datagrams", serverDatagrams, numDatagrams)
		assert.EqualValues(t, numDatagrams-numDroppedToServer, serverDatagrams, "datagrams received by the server")
		t.Logf("client received %d out of %d sent datagrams", clientDatagrams, numDatagrams)
		assert.EqualValues(t, numDatagrams-numDroppedToClient, clientDatagrams, "datagrams received by the client")
	})
}
