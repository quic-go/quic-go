package self_test

import (
	"bytes"
	"context"
	"math"
	mrand "math/rand/v2"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/internal/synctest"
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

	if clientEnableDatagram {
		require.True(t, serverConn.ConnectionState().SupportsDatagrams)
		require.NoError(t, serverConn.SendDatagram([]byte("foo")))
		datagram, err := clientConn.ReceiveDatagram(ctx)
		require.NoError(t, err)
		require.Equal(t, []byte("foo"), datagram)
	} else {
		require.False(t, serverConn.ConnectionState().SupportsDatagrams)
		require.Error(t, serverConn.SendDatagram([]byte("foo")))
	}

	if serverEnableDatagram {
		require.True(t, clientConn.ConnectionState().SupportsDatagrams)
		require.NoError(t, clientConn.SendDatagram([]byte("bar")))
		datagram, err := serverConn.ReceiveDatagram(ctx)
		require.NoError(t, err)
		require.Equal(t, []byte("bar"), datagram)
	} else {
		require.False(t, clientConn.ConnectionState().SupportsDatagrams)
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
		settings := simnet.NodeBiDiLinkSettings{
			Downlink: simnet.LinkSettings{BitsPerSecond: math.MaxInt, Latency: rtt / 4},
			Uplink:   simnet.LinkSettings{BitsPerSecond: math.MaxInt, Latency: rtt / 4},
		}
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

func TestMaxDatagramSize(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const rtt = 10 * time.Millisecond
		clientPacketConn, serverPacketConn, closeFn := newSimnetLink(t, rtt)
		defer closeFn(t)

		server, err := quic.Listen(
			serverPacketConn,
			getTLSConfig(),
			getQuicConfig(&quic.Config{EnableDatagrams: true}),
		)
		require.NoError(t, err)
		defer server.Close()

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		clientConn, err := quic.Dial(
			ctx,
			clientPacketConn,
			serverPacketConn.LocalAddr(),
			getTLSClientConfig(),
			getQuicConfig(&quic.Config{EnableDatagrams: true}),
		)
		require.NoError(t, err)
		defer clientConn.CloseWithError(0, "")

		serverConn, err := server.Accept(ctx)
		require.NoError(t, err)
		defer serverConn.CloseWithError(0, "")

		// Wait for handshake to complete and MTU discovery to settle
		// In synctest, time advances deterministically, so we can use a short sleep
		time.Sleep(100 * time.Millisecond)
		synctest.Wait() // Advance synctest time

		// Get the maximum datagram size from ConnectionState
		clientState := clientConn.ConnectionState()
		require.True(t, clientState.SupportsDatagrams, "client should support datagrams")
		require.Greater(t, clientState.MaxDatagramSize, uint16(0), "MaxDatagramSize should be greater than 0")

		serverState := serverConn.ConnectionState()
		require.True(t, serverState.SupportsDatagrams, "server should support datagrams")
		require.Greater(t, serverState.MaxDatagramSize, uint16(0), "MaxDatagramSize should be greater than 0")

		maxSize := clientState.MaxDatagramSize
		t.Logf("MaxDatagramSize reported: %d bytes", maxSize)

		// Test that a datagram of the reported maximum size can be sent
		payloadMax := bytes.Repeat([]byte("a"), int(maxSize))
		err = clientConn.SendDatagram(payloadMax)
		require.NoError(t, err, "sending datagram of MaxDatagramSize should succeed")

		// Wait a bit for the datagram to be received
		// In synctest, we can use a shorter timeout since time is controlled
		recvCtx, recvCancel := context.WithTimeout(ctx, time.Second)
		defer recvCancel()
		time.Sleep(50 * time.Millisecond)
		synctest.Wait() // Advance time to process the datagram
		received, err := serverConn.ReceiveDatagram(recvCtx)
		require.NoError(t, err, "receiving datagram of MaxDatagramSize should succeed")
		require.Equal(t, payloadMax, received, "received datagram should match sent datagram")

		// Test that a datagram of size+1 cannot be sent (or gets an error)
		payloadTooLarge := bytes.Repeat([]byte("b"), int(maxSize+1))
		err = clientConn.SendDatagram(payloadTooLarge)
		// The datagram should either be rejected immediately or dropped during packing
		// If it's rejected, we get an error. If it's accepted but dropped, we won't receive it.
		if err != nil {
			// If we get an error, verify it's a DatagramTooLargeError
			var sizeErr *quic.DatagramTooLargeError
			require.ErrorAs(t, err, &sizeErr, "error should be DatagramTooLargeError")
			t.Logf("Datagram of size %d was correctly rejected with error", maxSize+1)
		} else {
			// If no error, the datagram was accepted but might be dropped during packing
			// Try to receive it with a short timeout - if it doesn't arrive, it was dropped
			recvCtx2, recvCancel2 := context.WithTimeout(ctx, 100*time.Millisecond)
			defer recvCancel2()
			time.Sleep(50 * time.Millisecond)
			synctest.Wait() // Advance time to see if datagram arrives
			_, err := serverConn.ReceiveDatagram(recvCtx2)
			if err != nil {
				// If we get a timeout/context error, the datagram was dropped (which is expected)
				require.ErrorIs(t, err, context.DeadlineExceeded, "datagram of size+1 should be dropped or timeout")
				t.Logf("Datagram of size %d was accepted but dropped during packing (as expected)", maxSize+1)
			} else {
				// If we receive it, that's unexpected - the reported size was too conservative
				t.Errorf("Unexpectedly received datagram of size %d, but MaxDatagramSize was reported as %d", maxSize+1, maxSize)
			}
		}
	})
}
