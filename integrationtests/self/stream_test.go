package self_test

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"github.com/quic-go/quic-go"

	"golang.org/x/sync/errgroup"

	"github.com/stretchr/testify/require"
)

func TestBidirectionalStreamMultiplexing(t *testing.T) {
	const numStreams = 75

	runSendingPeer := func(conn quic.Connection) error {
		g := new(errgroup.Group)
		for i := 0; i < numStreams; i++ {
			str, err := conn.OpenStreamSync(context.Background())
			if err != nil {
				return err
			}
			data := GeneratePRData(50 * i)
			g.Go(func() error {
				if _, err := str.Write(data); err != nil {
					return err
				}
				return str.Close()
			})
			g.Go(func() error {
				dataRead, err := io.ReadAll(str)
				if err != nil {
					return err
				}
				if !bytes.Equal(dataRead, data) {
					return fmt.Errorf("data mismatch: %q != %q", dataRead, data)
				}
				return nil
			})
		}
		return g.Wait()
	}

	runReceivingPeer := func(conn quic.Connection) error {
		g := new(errgroup.Group)
		for i := 0; i < numStreams; i++ {
			str, err := conn.AcceptStream(context.Background())
			if err != nil {
				return err
			}
			g.Go(func() error {
				// shouldn't use io.Copy here
				// we should read from the stream as early as possible, to free flow control credit
				data, err := io.ReadAll(str)
				if err != nil {
					return err
				}
				if _, err := str.Write(data); err != nil {
					return err
				}
				return str.Close()
			})
		}
		return g.Wait()
	}

	t.Run("client -> server", func(t *testing.T) {
		ln, err := quic.ListenAddr(
			"localhost:0",
			getTLSConfig(),
			getQuicConfig(&quic.Config{
				MaxIncomingStreams:             10,
				InitialStreamReceiveWindow:     10000,
				InitialConnectionReceiveWindow: 5000,
			}),
		)
		require.NoError(t, err)
		defer ln.Close()

		client, err := quic.DialAddr(
			context.Background(),
			fmt.Sprintf("localhost:%d", ln.Addr().(*net.UDPAddr).Port),
			getTLSClientConfig(),
			getQuicConfig(&quic.Config{InitialConnectionReceiveWindow: 2000}),
		)
		require.NoError(t, err)

		conn, err := ln.Accept(context.Background())
		require.NoError(t, err)

		errChan := make(chan error, 1)
		go func() { errChan <- runReceivingPeer(conn) }()
		require.NoError(t, runSendingPeer(client))
		client.CloseWithError(0, "")

		select {
		case err := <-errChan:
			require.NoError(t, err)
		case <-time.After(time.Second):
			require.Fail(t, "timeout")
		}
		select {
		case <-conn.Context().Done():
		case <-time.After(time.Second):
			require.Fail(t, "timeout")
		}
	})

	t.Run("bidirectional", func(t *testing.T) {
		ln, err := quic.ListenAddr(
			"localhost:0",
			getTLSConfig(),
			getQuicConfig(&quic.Config{
				MaxIncomingStreams:             30,
				InitialStreamReceiveWindow:     25000,
				InitialConnectionReceiveWindow: 50000,
			}),
		)
		require.NoError(t, err)
		defer ln.Close()

		client, err := quic.DialAddr(
			context.Background(),
			fmt.Sprintf("localhost:%d", ln.Addr().(*net.UDPAddr).Port),
			getTLSClientConfig(),
			getQuicConfig(&quic.Config{InitialConnectionReceiveWindow: 2000}),
		)
		require.NoError(t, err)

		conn, err := ln.Accept(context.Background())
		require.NoError(t, err)

		errChan1 := make(chan error, 1)
		errChan2 := make(chan error, 1)
		errChan3 := make(chan error, 1)
		errChan4 := make(chan error, 1)

		go func() { errChan1 <- runReceivingPeer(conn) }()
		go func() { errChan2 <- runSendingPeer(conn) }()
		go func() { errChan3 <- runReceivingPeer(client) }()
		go func() { errChan4 <- runSendingPeer(client) }()

		for _, ch := range []chan error{errChan1, errChan2, errChan3, errChan4} {
			select {
			case err := <-ch:
				require.NoError(t, err)
			case <-time.After(time.Second):
				require.Fail(t, "timeout")
			}
		}

		client.CloseWithError(0, "")
		select {
		case <-conn.Context().Done():
		case <-time.After(time.Second):
			require.Fail(t, "timeout")
		}
	})
}
