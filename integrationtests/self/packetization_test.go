package self_test

import (
	"context"
	"fmt"
	"io"
	"os"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	quicproxy "github.com/quic-go/quic-go/integrationtests/tools/proxy"
	"github.com/quic-go/quic-go/logging"
	"github.com/quic-go/quic-go/quicvarint"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestACKBundling(t *testing.T) {
	const numMsg = 100

	serverCounter, serverTracer := newPacketTracer()
	server, err := quic.Listen(
		newUPDConnLocalhost(t),
		getTLSConfig(),
		getQuicConfig(&quic.Config{
			DisablePathMTUDiscovery: true,
			Tracer:                  newTracer(serverTracer),
		}),
	)
	require.NoError(t, err)
	defer server.Close()

	proxy, err := quicproxy.NewQuicProxy("localhost:0", &quicproxy.Opts{
		RemoteAddr: server.Addr().String(),
		DelayPacket: func(dir quicproxy.Direction, _ []byte) time.Duration {
			return 5 * time.Millisecond
		},
	})
	require.NoError(t, err)
	defer proxy.Close()

	clientCounter, clientTracer := newPacketTracer()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	conn, err := quic.Dial(
		ctx,
		newUPDConnLocalhost(t),
		proxy.LocalAddr(),
		getTLSClientConfig(),
		getQuicConfig(&quic.Config{
			DisablePathMTUDiscovery: true,
			Tracer:                  newTracer(clientTracer),
		}),
	)
	require.NoError(t, err)
	defer conn.CloseWithError(0, "")

	serverErrChan := make(chan error, 1)
	go func() {
		defer close(serverErrChan)
		conn, err := server.Accept(context.Background())
		if err != nil {
			serverErrChan <- fmt.Errorf("accept failed: %w", err)
			return
		}
		str, err := conn.AcceptStream(context.Background())
		if err != nil {
			serverErrChan <- fmt.Errorf("accept stream failed: %w", err)
			return
		}
		b := make([]byte, 1)
		// Echo every byte received from the client.
		for {
			if _, err := str.Read(b); err != nil {
				break
			}
			_, err = str.Write(b)
			if err != nil {
				serverErrChan <- fmt.Errorf("write failed: %w", err)
				return
			}
		}
	}()

	str, err := conn.OpenStreamSync(context.Background())
	require.NoError(t, err)
	b := make([]byte, 1)
	// Send numMsg 1-byte messages.
	for i := 0; i < numMsg; i++ {
		_, err = str.Write([]byte{uint8(i)})
		require.NoError(t, err)
		_, err = str.Read(b)
		require.NoError(t, err)
		require.Equal(t, uint8(i), b[0])
	}
	require.NoError(t, conn.CloseWithError(0, ""))
	require.NoError(t, <-serverErrChan)

	countBundledPackets := func(packets []shortHeaderPacket) (numBundled int) {
		for _, p := range packets {
			var hasAck, hasStreamFrame bool
			for _, f := range p.frames {
				switch f.(type) {
				case *logging.AckFrame:
					hasAck = true
				case *logging.StreamFrame:
					hasStreamFrame = true
				}
			}
			if hasAck && hasStreamFrame {
				numBundled++
			}
		}
		return
	}

	numBundledIncoming := countBundledPackets(clientCounter.getRcvdShortHeaderPackets())
	numBundledOutgoing := countBundledPackets(serverCounter.getRcvdShortHeaderPackets())
	t.Logf("bundled incoming packets: %d / %d", numBundledIncoming, numMsg)
	t.Logf("bundled outgoing packets: %d / %d", numBundledOutgoing, numMsg)

	require.LessOrEqual(t, numBundledIncoming, numMsg)
	require.Greater(t, numBundledIncoming, numMsg*9/10)
	require.LessOrEqual(t, numBundledOutgoing, numMsg)
	require.Greater(t, numBundledOutgoing, numMsg*9/10)
}

func TestStreamDataBlocked(t *testing.T) {
	testConnAndStreamDataBlocked(t, true, false)
}

func TestConnDataBlocked(t *testing.T) {
	testConnAndStreamDataBlocked(t, false, true)
}

func testConnAndStreamDataBlocked(t *testing.T, limitStream, limitConn bool) {
	initialStreamWindow := uint64(quicvarint.Max)
	initialConnWindow := uint64(quicvarint.Max)
	if limitStream {
		initialStreamWindow = 100
	}
	if limitConn {
		initialConnWindow = 100
	}

	ln, err := quic.Listen(
		newUPDConnLocalhost(t),
		getTLSConfig(),
		getQuicConfig(&quic.Config{
			InitialStreamReceiveWindow:     initialStreamWindow,
			InitialConnectionReceiveWindow: initialConnWindow,
		}),
	)
	require.NoError(t, err)
	defer ln.Close()

	counter, tracer := newPacketTracer()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	conn, err := quic.Dial(
		ctx,
		newUPDConnLocalhost(t),
		ln.Addr(),
		getTLSClientConfig(),
		getQuicConfig(&quic.Config{
			Tracer: func(context.Context, logging.Perspective, quic.ConnectionID) *logging.ConnectionTracer {
				return tracer
			},
		}),
	)
	require.NoError(t, err)

	serverConn, err := ln.Accept(ctx)
	require.NoError(t, err)

	str, err := conn.OpenUniStreamSync(ctx)
	require.NoError(t, err)

	var serverStr quic.ReceiveStream
	for i := 0; i < 3; i++ {
		str.SetWriteDeadline(time.Now().Add(scaleDuration(10 * time.Millisecond)))
		n, err := str.Write(make([]byte, 10000))
		require.Error(t, err)
		require.ErrorIs(t, err, os.ErrDeadlineExceeded)
		require.Equal(t, 100, n)

		if i == 0 {
			serverStr, err = serverConn.AcceptUniStream(ctx)
			require.NoError(t, err)
		}
		serverStr.SetReadDeadline(time.Now().Add(scaleDuration(10 * time.Millisecond)))
		n2, err := io.ReadFull(serverStr, make([]byte, 10000))
		require.Error(t, err)
		require.ErrorIs(t, err, os.ErrDeadlineExceeded)
		require.Equal(t, n, n2)
	}

	conn.CloseWithError(0, "")
	serverConn.CloseWithError(0, "")

	var streamDataBlockedFrames []logging.StreamDataBlockedFrame
	var dataBlockedFrames []logging.DataBlockedFrame
	for _, p := range counter.getSentShortHeaderPackets() {
		for _, f := range p.frames {
			switch frame := f.(type) {
			case *logging.StreamDataBlockedFrame:
				streamDataBlockedFrames = append(streamDataBlockedFrames, *frame)
			case *logging.DataBlockedFrame:
				dataBlockedFrames = append(dataBlockedFrames, *frame)
			}
		}
	}
	if limitStream {
		assert.Len(t, streamDataBlockedFrames, 3)
		for i, f := range streamDataBlockedFrames {
			assert.Equal(t, str.StreamID(), f.StreamID)
			assert.Equal(t, logging.ByteCount(100*(i+1)), f.MaximumStreamData)
		}
		assert.Empty(t, dataBlockedFrames)
	}
	if limitConn {
		assert.Len(t, dataBlockedFrames, 3)
		for i, f := range dataBlockedFrames {
			assert.Equal(t, logging.ByteCount(100*(i+1)), f.MaximumData)
		}
		assert.Empty(t, streamDataBlockedFrames)
	}
}
