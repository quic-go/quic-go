package self_test

import (
	"context"
	"io"
	"testing"
	"testing/synctest"
	"time"

	"github.com/quic-go/quic-go"

	"github.com/stretchr/testify/require"
)

func TestEarlyData(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const rtt = 80 * time.Millisecond
		clientPacketConn, serverPacketConn, closeFn := newSimnetLink(t, rtt)
		defer closeFn(t)

		ln, err := quic.ListenEarly(serverPacketConn, getTLSConfig(), getQuicConfig(nil))
		require.NoError(t, err)
		defer ln.Close()

		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		clientConn, err := quic.Dial(ctx, clientPacketConn, ln.Addr(), getTLSClientConfig(), getQuicConfig(nil))
		require.NoError(t, err)

		serverConn, err := ln.Accept(ctx)
		require.NoError(t, err)
		str, err := serverConn.OpenUniStream()
		require.NoError(t, err)
		_, err = str.Write([]byte("early data"))
		require.NoError(t, err)
		require.NoError(t, str.Close())
		// the write should have completed before the handshake
		select {
		case <-serverConn.HandshakeComplete():
			t.Fatal("handshake shouldn't be completed yet")
		default:
		}

		clientStr, err := clientConn.AcceptUniStream(context.Background())
		require.NoError(t, err)
		data, err := io.ReadAll(clientStr)
		require.NoError(t, err)
		require.Equal(t, []byte("early data"), data)

		clientConn.CloseWithError(0, "")
		<-serverConn.Context().Done()
	})
}
