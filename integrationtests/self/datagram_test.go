package self_test

import (
	"bytes"
	"context"
	mrand "math/rand/v2"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	quicproxy "github.com/quic-go/quic-go/integrationtests/tools/proxy"
	"github.com/quic-go/quic-go/internal/wire"

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
	const rtt = 10 * time.Millisecond
	const numDatagrams = 100
	const datagramSize = 500

	server, err := quic.Listen(
		newUDPConnLocalhost(t),
		getTLSConfig(),
		getQuicConfig(&quic.Config{EnableDatagrams: true}),
	)
	require.NoError(t, err)
	defer server.Close()

	var droppedIncoming, droppedOutgoing, total atomic.Int32
	proxy := &quicproxy.Proxy{
		Conn:       newUDPConnLocalhost(t),
		ServerAddr: server.Addr().(*net.UDPAddr),
		DropPacket: func(dir quicproxy.Direction, _, _ net.Addr, packet []byte) bool {
			if wire.IsLongHeaderPacket(packet[0]) { // don't drop Long Header packets
				return false
			}
			if len(packet) < datagramSize { // don't drop ACK-only packets
				return false
			}
			total.Add(1)
			if mrand.Int()%10 == 0 {
				switch dir {
				case quicproxy.DirectionIncoming:
					droppedIncoming.Add(1)
				case quicproxy.DirectionOutgoing:
					droppedOutgoing.Add(1)
				}
				return true
			}
			return false
		},
		DelayPacket: func(quicproxy.Direction, net.Addr, net.Addr, []byte) time.Duration { return rtt / 2 },
	}
	require.NoError(t, proxy.Start())
	defer proxy.Close()

	ctx, cancel := context.WithTimeout(context.Background(), scaleDuration(numDatagrams*time.Millisecond))
	defer cancel()
	clientConn, err := quic.Dial(
		ctx,
		newUDPConnLocalhost(t),
		proxy.LocalAddr(),
		getTLSClientConfig(),
		getQuicConfig(&quic.Config{EnableDatagrams: true}),
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

	for i := 0; i < numDatagrams; i++ {
		payload := bytes.Repeat([]byte{uint8(i)}, datagramSize)
		require.NoError(t, clientConn.SendDatagram(payload))
		require.NoError(t, serverConn.SendDatagram(payload))
		time.Sleep(scaleDuration(time.Millisecond / 2))
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
	case <-time.After(scaleDuration(5 * numDatagrams * time.Millisecond)):
		t.Fatal("timeout")
	}
	select {
	case err := <-serverErrChan:
		require.ErrorIs(t, err, context.DeadlineExceeded)
	case <-time.After(scaleDuration(5 * numDatagrams * time.Millisecond)):
		t.Fatal("timeout")
	}

	numDroppedIncoming := droppedIncoming.Load()
	numDroppedOutgoing := droppedOutgoing.Load()
	t.Logf("dropped %d incoming and %d outgoing out of %d packets", numDroppedIncoming, numDroppedOutgoing, total.Load())
	assert.NotZero(t, numDroppedIncoming)
	assert.NotZero(t, numDroppedOutgoing)
	t.Logf("server received %d out of %d sent datagrams", serverDatagrams, numDatagrams)
	assert.InDelta(t, numDatagrams-numDroppedIncoming, serverDatagrams, numDatagrams/20, "datagrams received by the server")
	t.Logf("client received %d out of %d sent datagrams", clientDatagrams, numDatagrams)
	assert.InDelta(t, numDatagrams-numDroppedOutgoing, clientDatagrams, numDatagrams/20, "datagrams received by the client")
}
