package self_test

import (
	"context"
	"crypto/rand"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/testutils/simnet"

	"github.com/stretchr/testify/require"
)

func TestStatelessResets(t *testing.T) {
	t.Run("zero-length connection IDs", func(t *testing.T) {
		testStatelessReset(t, 0)
	})
	t.Run("10 byte connection IDs", func(t *testing.T) {
		testStatelessReset(t, 10)
	})
}

func testStatelessReset(t *testing.T, connIDLen int) {
	synctest.Test(t, func(t *testing.T) {
		var drop atomic.Bool
		clientPacketConn, serverPacketConn, closeFn := newSimnetLinkWithRouter(t,
			time.Millisecond,
			&droppingRouter{Drop: func(p simnet.Packet) bool { return drop.Load() }},
		)
		defer closeFn(t)

		var statelessResetKey quic.StatelessResetKey
		rand.Read(statelessResetKey[:])

		tr := &quic.Transport{
			Conn:              serverPacketConn,
			StatelessResetKey: &statelessResetKey,
		}
		defer tr.Close()

		ln, err := tr.Listen(getTLSConfig(), getQuicConfig(nil))
		require.NoError(t, err)

		serverErr := make(chan error, 1)
		go func() {
			conn, err := ln.Accept(context.Background())
			if err != nil {
				serverErr <- err
				return
			}
			str, err := conn.OpenStream()
			if err != nil {
				serverErr <- err
				return
			}
			_, err = str.Write([]byte("foobar"))
			if err != nil {
				serverErr <- err
				return
			}
			close(serverErr)
		}()

		var conn *quic.Conn
		if connIDLen > 0 {
			cl := &quic.Transport{
				Conn:               clientPacketConn,
				ConnectionIDLength: connIDLen,
			}
			defer cl.Close()
			var err error
			conn, err = cl.Dial(
				context.Background(),
				serverPacketConn.LocalAddr(),
				getTLSClientConfig(),
				getQuicConfig(&quic.Config{MaxIdleTimeout: 2 * time.Second}),
			)
			require.NoError(t, err)
		} else {
			conn, err = quic.Dial(
				context.Background(),
				clientPacketConn,
				serverPacketConn.LocalAddr(),
				getTLSClientConfig(),
				getQuicConfig(&quic.Config{MaxIdleTimeout: 2 * time.Second}),
			)
			require.NoError(t, err)
		}
		str, err := conn.AcceptStream(context.Background())
		require.NoError(t, err)
		data := make([]byte, 6)
		_, err = str.Read(data)
		require.NoError(t, err)
		require.Equal(t, []byte("foobar"), data)

		// make sure that the CONNECTION_CLOSE is dropped
		drop.Store(true)
		require.NoError(t, ln.Close())
		require.NoError(t, tr.Close())
		require.NoError(t, <-serverErr)
		time.Sleep(100 * time.Millisecond)

		// We need to create a new Transport here, since the old one is still sending out
		// CONNECTION_CLOSE packets for (recently) closed connections).
		tr2 := &quic.Transport{
			Conn:              serverPacketConn,
			StatelessResetKey: &statelessResetKey,
		}
		defer tr2.Close()
		ln2, err := tr2.Listen(getTLSConfig(), getQuicConfig(nil))
		require.NoError(t, err)
		drop.Store(false)

		// Trigger something (not too small) to be sent, so that we receive the stateless reset.
		// If the client already sent another packet, it might already have received a packet.
		_, serr := str.Write([]byte("Lorem ipsum dolor sit amet."))
		if serr == nil {
			_, serr = str.Read([]byte{0})
		}
		require.Error(t, serr)
		require.IsType(t, &quic.StatelessResetError{}, serr)
		require.NoError(t, ln2.Close())
	})
}
