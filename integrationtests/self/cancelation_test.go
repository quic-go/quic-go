package self_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/internal/protocol"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStreamReadCancellation(t *testing.T) {
	t.Run("immediate", func(t *testing.T) {
		testStreamCancellation(t, func(str quic.ReceiveStream) error {
			str.CancelRead(quic.StreamErrorCode(str.StreamID()))
			_, err := str.Read([]byte{0})
			return err
		}, nil)
	})

	t.Run("after reading some data", func(t *testing.T) {
		testStreamCancellation(t, func(str quic.ReceiveStream) error {
			length := int(rand.Int31n(int32(len(PRData) - 1)))
			if _, err := io.ReadAll(io.LimitReader(str, int64(length))); err != nil {
				return fmt.Errorf("reading stream data failed: %w", err)
			}
			str.CancelRead(quic.StreamErrorCode(str.StreamID()))
			_, err := str.Read([]byte{0})
			return err
		}, nil)
	})

	// This test is especially valuable when run with race detector,
	// see https://github.com/quic-go/quic-go/issues/3239.
	t.Run("concurrent", func(t *testing.T) {
		testStreamCancellation(t, func(str quic.ReceiveStream) error {
			errChan := make(chan error, 1)
			go func() {
				for {
					if _, err := str.Read(make([]byte, 16)); err != nil {
						errChan <- err
						return
					}
					time.Sleep(time.Millisecond)
				}
			}()

			done := make(chan struct{})
			go func() {
				defer close(done)
				str.CancelRead(quic.StreamErrorCode(str.StreamID()))
			}()

			timeout := time.After(time.Second)
			select {
			case <-done:
			case <-timeout:
				return fmt.Errorf("timeout canceling")
			}
			select {
			case err := <-errChan:
				return err
			case <-timeout:
				return fmt.Errorf("timeout canceling")
			}
		}, nil)
	})
}

func TestStreamWriteCancellation(t *testing.T) {
	t.Run("immediate", func(t *testing.T) {
		testStreamCancellation(t, nil, func(str quic.SendStream) error {
			str.CancelWrite(quic.StreamErrorCode(str.StreamID()))
			_, err := str.Write([]byte{0})
			return err
		})
	})

	t.Run("after writing some data", func(t *testing.T) {
		testStreamCancellation(t, nil, func(str quic.SendStream) error {
			length := int(rand.Int31n(int32(len(PRData) - 1)))
			if _, err := str.Write(PRData[:length]); err != nil {
				return fmt.Errorf("writing stream data failed: %w", err)
			}
			str.CancelWrite(quic.StreamErrorCode(str.StreamID()))
			_, err := str.Write([]byte{0})
			return err
		})
	})

	// This test is especially valuable when run with race detector,
	// see https://github.com/quic-go/quic-go/issues/3239.
	t.Run("concurrent", func(t *testing.T) {
		testStreamCancellation(t, nil, func(str quic.SendStream) error {
			errChan := make(chan error, 1)
			go func() {
				var offset int
				for {
					n, err := str.Write(PRData[offset : offset+128])
					if err != nil {
						errChan <- err
						return
					}
					offset += n
					time.Sleep(time.Millisecond)
				}
			}()

			done := make(chan struct{})
			go func() {
				defer close(done)
				str.CancelWrite(quic.StreamErrorCode(str.StreamID()))
			}()

			timeout := time.After(time.Second)
			select {
			case <-done:
			case <-timeout:
				return fmt.Errorf("timeout canceling")
			}
			select {
			case err := <-errChan:
				return err
			case <-timeout:
				return fmt.Errorf("timeout canceling")
			}
		})
	})
}

func TestStreamReadWriteCancellation(t *testing.T) {
	t.Run("immediate", func(t *testing.T) {
		testStreamCancellation(t,
			func(str quic.ReceiveStream) error {
				str.CancelRead(quic.StreamErrorCode(str.StreamID()))
				_, err := str.Read([]byte{0})
				return err
			},
			func(str quic.SendStream) error {
				str.CancelWrite(quic.StreamErrorCode(str.StreamID()))
				_, err := str.Write([]byte{0})
				return err
			},
		)
	})

	t.Run("after writing some data", func(t *testing.T) {
		testStreamCancellation(t,
			func(str quic.ReceiveStream) error {
				length := int(rand.Int31n(int32(len(PRData) - 1)))
				if _, err := io.ReadAll(io.LimitReader(str, int64(length))); err != nil {
					return fmt.Errorf("reading stream data failed: %w", err)
				}
				str.CancelRead(quic.StreamErrorCode(str.StreamID()))
				_, err := str.Read([]byte{0})
				return err
			},
			func(str quic.SendStream) error {
				length := int(rand.Int31n(int32(len(PRData) - 1)))
				if _, err := str.Write(PRData[:length]); err != nil {
					return fmt.Errorf("writing stream data failed: %w", err)
				}
				str.CancelWrite(quic.StreamErrorCode(str.StreamID()))
				_, err := str.Write([]byte{0})
				return err
			},
		)
	})
}

// If readFunc is set, the read side is canceled for 50% of the streams.
// If writeFunc is set, the write side is canceled for 50% of the streams.
func testStreamCancellation(
	t *testing.T,
	readFunc func(str quic.ReceiveStream) error,
	writeFunc func(str quic.SendStream) error,
) {
	const numStreams = 80

	server, err := quic.Listen(newUDPConnLocalhost(t), getTLSConfig(), getQuicConfig(nil))
	require.NoError(t, err)
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), scaleDuration(2*time.Second))
	defer cancel()
	conn, err := quic.Dial(
		ctx,
		newUDPConnLocalhost(t),
		server.Addr(),
		getTLSClientConfig(),
		getQuicConfig(&quic.Config{MaxIncomingUniStreams: numStreams / 2}),
	)
	require.NoError(t, err)
	defer conn.CloseWithError(0, "")

	serverConn, err := server.Accept(ctx)
	require.NoError(t, err)

	type cancellationErr struct {
		StreamID quic.StreamID
		Err      error
	}

	var numCancellations int
	actions := make([]bool, numStreams)
	for i := range actions {
		actions[i] = rand.Intn(2) == 0
		if actions[i] {
			numCancellations++
		}
	}

	// The server accepts a single connection, and then opens numStreams unidirectional streams.
	// On each of these streams, it (tries to) write PRData.
	serverErrChan := make(chan *cancellationErr, numStreams)
	go func() {
		for _, doCancel := range actions {
			str, err := serverConn.OpenUniStreamSync(ctx)
			if err != nil {
				serverErrChan <- &cancellationErr{StreamID: protocol.InvalidStreamID, Err: fmt.Errorf("opening stream failed: %w", err)}
				return
			}
			go func() {
				if writeFunc != nil && doCancel {
					if err := writeFunc(str); err != nil {
						serverErrChan <- &cancellationErr{StreamID: str.StreamID(), Err: err}
						return
					}
					serverErrChan <- nil
					return
				}
				defer str.Close()
				if _, err := str.Write(PRData); err != nil {
					serverErrChan <- &cancellationErr{StreamID: str.StreamID(), Err: err}
					return
				}
				serverErrChan <- nil
			}()
		}
	}()

	clientErrChan := make(chan *cancellationErr, numStreams)
	for _, doCancel := range actions {
		str, err := conn.AcceptUniStream(ctx)
		require.NoError(t, err)
		go func(str quic.ReceiveStream) {
			if readFunc != nil && doCancel {
				if err := readFunc(str); err != nil {
					clientErrChan <- &cancellationErr{StreamID: str.StreamID(), Err: err}
					return
				}
			}
			data, err := io.ReadAll(str)
			if err != nil {
				clientErrChan <- &cancellationErr{StreamID: str.StreamID(), Err: fmt.Errorf("reading stream data failed: %w", err)}
				return
			}
			if !bytes.Equal(data, PRData) {
				clientErrChan <- &cancellationErr{StreamID: str.StreamID(), Err: fmt.Errorf("received data mismatch")}
				return
			}
			clientErrChan <- nil
		}(str)
	}

	timeout := time.After(time.Second)
	var clientErrs, serverErrs int
	for range numStreams {
		select {
		case err := <-serverErrChan:
			if err != nil {
				if err.StreamID == protocol.InvalidStreamID { // failed opening a stream
					require.NoError(t, err.Err)
					continue
				}
				var streamErr *quic.StreamError
				require.ErrorAs(t, err.Err, &streamErr)
				assert.Equal(t, streamErr.StreamID, err.StreamID)
				assert.Equal(t, streamErr.ErrorCode, quic.StreamErrorCode(err.StreamID))
				if readFunc != nil && writeFunc == nil {
					assert.Equal(t, streamErr.Remote, readFunc != nil)
				}
				serverErrs++
			}
		case <-timeout:
			t.Fatalf("timeout")
		}
		select {
		case err := <-clientErrChan:
			if err != nil {
				if err.StreamID == protocol.InvalidStreamID { // failed accepting a stream
					require.NoError(t, err.Err)
					continue
				}
				var streamErr *quic.StreamError
				require.ErrorAs(t, err.Err, &streamErr)
				assert.Equal(t, streamErr.StreamID, err.StreamID)
				assert.Equal(t, streamErr.ErrorCode, quic.StreamErrorCode(err.StreamID))
				if readFunc != nil && writeFunc == nil {
					assert.Equal(t, streamErr.Remote, writeFunc != nil)
				}
				clientErrs++
			}
		case <-timeout:
			t.Fatalf("timeout")
		}
	}
	assert.Equal(t, numCancellations, clientErrs, "client canceled streams")
	// The server will only count a stream as being reset if it learns about the cancellation
	// before it finished writing all data.
	assert.LessOrEqual(t, serverErrs, numCancellations, "server-observed canceled streams")
	assert.NotZero(t, serverErrs, "server-observed canceled streams")
}

func TestCancelAcceptStream(t *testing.T) {
	const numStreams = 30

	server, err := quic.Listen(newUDPConnLocalhost(t), getTLSConfig(), getQuicConfig(nil))
	require.NoError(t, err)
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	conn, err := quic.Dial(
		ctx,
		newUDPConnLocalhost(t),
		server.Addr(),
		getTLSClientConfig(),
		getQuicConfig(&quic.Config{MaxIncomingUniStreams: numStreams / 3}),
	)
	require.NoError(t, err)
	defer conn.CloseWithError(0, "")

	serverConn, err := server.Accept(ctx)
	require.NoError(t, err)
	defer conn.CloseWithError(0, "")

	serverErrChan := make(chan error, 1)
	go func() {
		defer close(serverErrChan)
		ctx, cancel := context.WithTimeout(context.Background(), scaleDuration(2*time.Second))
		defer cancel()
		ticker := time.NewTicker(5 * time.Millisecond)
		defer ticker.Stop()
		for i := 0; i < numStreams; i++ {
			<-ticker.C
			str, err := serverConn.OpenUniStreamSync(ctx)
			if err != nil {
				serverErrChan <- err
				return
			}
			if _, err := str.Write(PRData); err != nil {
				serverErrChan <- err
				return
			}
			str.Close()
		}
	}()

	var numToAccept int
	var counter atomic.Int32
	var wg sync.WaitGroup
	wg.Add(numStreams)
	for numToAccept < numStreams {
		ctx, cancel := context.WithCancel(context.Background())
		// cancel accepting half of the streams
		if rand.Int31()%2 == 0 {
			cancel()
		} else {
			numToAccept++
			defer cancel()
		}

		go func() {
			str, err := conn.AcceptUniStream(ctx)
			if err != nil {
				if errors.Is(err, context.Canceled) {
					counter.Add(1)
				}
				return
			}
			go func() {
				data, err := io.ReadAll(str)
				if err != nil {
					t.Errorf("ReadAll failed: %v", err)
					return
				}
				if !bytes.Equal(data, PRData) {
					t.Errorf("received data mismatch")
					return
				}
				wg.Done()
			}()
		}()
	}
	wg.Wait()

	count := counter.Load()
	t.Logf("canceled AcceptStream %d times", count)
	require.Greater(t, count, int32(numStreams/4))
	require.NoError(t, conn.CloseWithError(0, ""))
	require.NoError(t, server.Close())
	require.NoError(t, <-serverErrChan)
}

func TestCancelOpenStreamSync(t *testing.T) {
	const (
		numStreams         = 16
		maxIncomingStreams = 4
	)

	server, err := quic.Listen(newUDPConnLocalhost(t), getTLSConfig(), getQuicConfig(nil))
	require.NoError(t, err)
	defer server.Close()

	conn, err := quic.Dial(
		context.Background(),
		newUDPConnLocalhost(t),
		server.Addr(),
		getTLSClientConfig(),
		getQuicConfig(&quic.Config{MaxIncomingUniStreams: maxIncomingStreams}),
	)
	require.NoError(t, err)

	msg := make(chan struct{}, 1)
	serverErrChan := make(chan error, numStreams+1)
	var numCanceled int
	serverConn, err := server.Accept(context.Background())
	require.NoError(t, err)
	go func() {
		defer close(msg)
		var numOpened int
		for numOpened < numStreams {
			ctx, cancel := context.WithTimeout(context.Background(), scaleDuration(10*time.Millisecond))
			defer cancel()
			str, err := serverConn.OpenUniStreamSync(ctx)
			if err != nil {
				if !errors.Is(err, context.DeadlineExceeded) {
					serverErrChan <- err
					return
				}
				numCanceled++
				select {
				case msg <- struct{}{}:
				default:
				}
				continue
			}
			numOpened++
			go func(str quic.SendStream) {
				defer str.Close()
				if _, err := str.Write(PRData); err != nil {
					serverErrChan <- err
				}
			}(str)
		}
	}()

	clientErrChan := make(chan error, numStreams)
	for i := 0; i < numStreams; i++ {
		<-msg
		str, err := conn.AcceptUniStream(context.Background())
		require.NoError(t, err)
		go func(str quic.ReceiveStream) {
			data, err := io.ReadAll(str)
			if err != nil {
				clientErrChan <- err
				return
			}
			if !bytes.Equal(data, PRData) {
				clientErrChan <- fmt.Errorf("received data mismatch")
				return
			}
			clientErrChan <- nil
		}(str)
	}

	timeout := time.After(scaleDuration(2 * time.Second))
	for range numStreams {
		select {
		case err := <-clientErrChan:
			require.NoError(t, err)
		case err := <-serverErrChan:
			require.NoError(t, err)
		case <-timeout:
			t.Fatalf("timeout")
		}
	}

	count := numCanceled
	t.Logf("Canceled OpenStreamSync %d times", count)
	require.GreaterOrEqual(t, count, numStreams-maxIncomingStreams)
	require.NoError(t, conn.CloseWithError(0, ""))
	require.NoError(t, server.Close())
}

func TestHeavyStreamCancellation(t *testing.T) {
	const maxIncomingStreams = 500

	server, err := quic.Listen(
		newUDPConnLocalhost(t),
		getTLSConfig(),
		getQuicConfig(&quic.Config{MaxIncomingStreams: maxIncomingStreams, MaxIdleTimeout: 10 * time.Second}),
	)
	require.NoError(t, err)
	defer server.Close()

	var wg sync.WaitGroup
	wg.Add(2 * 4 * maxIncomingStreams)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	conn, err := quic.Dial(ctx, newUDPConnLocalhost(t), server.Addr(), getTLSClientConfig(), getQuicConfig(nil))
	require.NoError(t, err)

	serverConn, err := server.Accept(context.Background())
	require.NoError(t, err)

	handleStream := func(str quic.Stream) {
		str.SetDeadline(time.Now().Add(time.Second))
		go func() {
			defer wg.Done()
			if rand.Int31()%2 == 0 {
				io.ReadAll(str)
			}
		}()
		go func() {
			defer wg.Done()
			if rand.Int31()%2 == 0 {
				str.Write([]byte("foobar"))
				if rand.Int31()%2 == 0 {
					str.Close()
				}
			}
		}()
		go func() {
			defer wg.Done()
			// Make sure we at least send out *something* for the last stream,
			// otherwise the peer might never receive this anything for this stream.
			if rand.Int31()%2 == 0 || str.StreamID() == 4*(maxIncomingStreams-1) {
				str.CancelWrite(1234)
			}
		}()
		go func() {
			defer wg.Done()
			if rand.Int31()%2 == 0 {
				str.CancelRead(1234)
			}
		}()
	}

	serverErrChan := make(chan error, 1)
	go func() {
		defer close(serverErrChan)

		for {
			str, err := serverConn.AcceptStream(context.Background())
			if err != nil {
				serverErrChan <- err
				return
			}
			handleStream(str)
		}
	}()

	for i := 0; i < maxIncomingStreams; i++ {
		str, err := conn.OpenStreamSync(context.Background())
		require.NoError(t, err)
		handleStream(str)
	}

	// We don't expect to accept any stream here.
	// We're just making sure the connection stays open and there's no error.
	ctx, cancel = context.WithTimeout(context.Background(), scaleDuration(50*time.Millisecond))
	defer cancel()
	_, err = conn.AcceptStream(ctx)
	require.ErrorIs(t, err, context.DeadlineExceeded)

	wg.Wait()

	require.NoError(t, conn.CloseWithError(0, ""))
	select {
	case err := <-serverErrChan:
		require.IsType(t, &quic.ApplicationError{}, err)
	case <-time.After(scaleDuration(time.Second)):
		t.Fatal("timeout waiting for server to stop")
	}
}
