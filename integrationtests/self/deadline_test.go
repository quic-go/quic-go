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

	"github.com/stretchr/testify/require"
)

func setupDeadlineTest(t *testing.T) (serverStr, clientStr quic.Stream) {
	t.Helper()
	server, err := quic.Listen(newUDPConnLocalhost(t), getTLSConfig(), getQuicConfig(nil))
	require.NoError(t, err)
	t.Cleanup(func() { server.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	conn, err := quic.Dial(ctx, newUDPConnLocalhost(t), server.Addr(), getTLSClientConfig(), getQuicConfig(nil))
	require.NoError(t, err)
	t.Cleanup(func() { conn.CloseWithError(0, "") })
	clientStr, err = conn.OpenStream()
	require.NoError(t, err)
	_, err = clientStr.Write([]byte{0}) // need to write one byte so the server learns about the stream
	require.NoError(t, err)

	serverConn, err := server.Accept(ctx)
	require.NoError(t, err)
	t.Cleanup(func() { serverConn.CloseWithError(0, "") })
	serverStr, err = serverConn.AcceptStream(ctx)
	require.NoError(t, err)

	_, err = serverStr.Read([]byte{0})
	require.NoError(t, err)
	return serverStr, clientStr
}

func TestReadDeadlineSync(t *testing.T) {
	serverStr, clientStr := setupDeadlineTest(t)

	const timeout = time.Millisecond
	errChan := make(chan error, 1)
	go func() {
		_, err := serverStr.Write(PRDataLong)
		errChan <- err
	}()

	var bytesRead int
	var timeoutCounter int
	buf := make([]byte, 1<<10)
	data := make([]byte, len(PRDataLong))
	clientStr.SetReadDeadline(time.Now().Add(timeout))
	for bytesRead < len(PRDataLong) {
		n, err := clientStr.Read(buf)
		if nerr, ok := err.(net.Error); ok && nerr.Timeout() {
			timeoutCounter++
			clientStr.SetReadDeadline(time.Now().Add(timeout))
		} else {
			require.NoError(t, err)
		}
		copy(data[bytesRead:], buf[:n])
		bytesRead += n
	}
	require.Equal(t, PRDataLong, data)
	// make sure the test actually worked and Read actually ran into the deadline a few times
	t.Logf("ran into deadline %d times", timeoutCounter)
	require.GreaterOrEqual(t, timeoutCounter, 10)
	select {
	case err := <-errChan:
		require.NoError(t, err)
	case <-time.After(time.Second):
		t.Fatal("timeout")
	}
}

func TestReadDeadlineAsync(t *testing.T) {
	serverStr, clientStr := setupDeadlineTest(t)

	const timeout = time.Millisecond
	errChan := make(chan error, 1)
	go func() {
		_, err := serverStr.Write(PRDataLong)
		errChan <- err
	}()

	var bytesRead int
	var timeoutCounter int
	buf := make([]byte, 1<<10)
	data := make([]byte, len(PRDataLong))
	received := make(chan struct{})
	go func() {
		for {
			select {
			case <-received:
				return
			default:
				time.Sleep(timeout)
			}
			clientStr.SetReadDeadline(time.Now().Add(timeout))
		}
	}()

	for bytesRead < len(PRDataLong) {
		n, err := clientStr.Read(buf)
		if nerr, ok := err.(net.Error); ok && nerr.Timeout() {
			timeoutCounter++
		} else {
			require.NoError(t, err)
		}
		copy(data[bytesRead:], buf[:n])
		bytesRead += n
	}

	require.Equal(t, PRDataLong, data)
	close(received)

	// make sure the test actually worked and Read actually ran into the deadline a few times
	t.Logf("ran into deadline %d times", timeoutCounter)
	require.GreaterOrEqual(t, timeoutCounter, 10)
	select {
	case err := <-errChan:
		require.NoError(t, err)
	case <-time.After(time.Second):
		t.Fatal("timeout")
	}
}

func TestWriteDeadlineSync(t *testing.T) {
	serverStr, clientStr := setupDeadlineTest(t)

	const timeout = time.Millisecond

	errChan := make(chan error, 1)
	go func() {
		defer close(errChan)
		data, err := io.ReadAll(serverStr)
		if err != nil {
			errChan <- err
		}
		if !bytes.Equal(PRDataLong, data) {
			errChan <- fmt.Errorf("data mismatch")
		}
	}()

	var bytesWritten int
	var timeoutCounter int
	clientStr.SetWriteDeadline(time.Now().Add(timeout))
	for bytesWritten < len(PRDataLong) {
		n, err := clientStr.Write(PRDataLong[bytesWritten:])
		if nerr, ok := err.(net.Error); ok && nerr.Timeout() {
			timeoutCounter++
			clientStr.SetWriteDeadline(time.Now().Add(timeout))
		} else {
			require.NoError(t, err)
		}
		bytesWritten += n
	}
	clientStr.Close()

	// make sure the test actually worked and Write actually ran into the deadline a few times
	t.Logf("ran into deadline %d times", timeoutCounter)
	require.GreaterOrEqual(t, timeoutCounter, 10)
	select {
	case err := <-errChan:
		require.NoError(t, err)
	case <-time.After(time.Second):
		t.Fatal("timeout")
	}
}

func TestWriteDeadlineAsync(t *testing.T) {
	serverStr, clientStr := setupDeadlineTest(t)

	const timeout = time.Millisecond

	errChan := make(chan error, 1)
	go func() {
		defer close(errChan)
		data, err := io.ReadAll(serverStr)
		if err != nil {
			errChan <- err
		}
		if !bytes.Equal(PRDataLong, data) {
			errChan <- fmt.Errorf("data mismatch")
		}
	}()

	clientStr.SetWriteDeadline(time.Now().Add(timeout))
	readDone := make(chan struct{})
	deadlineDone := make(chan struct{})
	go func() {
		defer close(deadlineDone)
		for {
			select {
			case <-readDone:
				return
			default:
				time.Sleep(timeout)
			}
			clientStr.SetWriteDeadline(time.Now().Add(timeout))
		}
	}()

	var bytesWritten int
	var timeoutCounter int
	clientStr.SetWriteDeadline(time.Now().Add(timeout))
	for bytesWritten < len(PRDataLong) {
		n, err := clientStr.Write(PRDataLong[bytesWritten:])
		if nerr, ok := err.(net.Error); ok && nerr.Timeout() {
			timeoutCounter++
		} else {
			require.NoError(t, err)
		}
		bytesWritten += n
	}
	clientStr.Close()

	close(readDone)

	// make sure the test actually worked and Write actually ran into the deadline a few times
	t.Logf("ran into deadline %d times", timeoutCounter)
	require.GreaterOrEqual(t, timeoutCounter, 10)
	select {
	case err := <-errChan:
		require.NoError(t, err)
	case <-time.After(time.Second):
		t.Fatal("timeout")
	}
}
