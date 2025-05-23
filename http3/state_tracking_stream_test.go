package http3

import (
	"context"
	"io"
	"net"
	"os"
	"testing"
	"time"

	"github.com/quic-go/quic-go"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newStreamPair(t *testing.T) (client, server *quic.Stream) {
	t.Helper()

	clientConn, serverConn := newConnPair(t)
	serverStr, err := serverConn.OpenStream()
	require.NoError(t, err)
	// need to send something to the client to make it accept the stream
	_, err = serverStr.Write([]byte{0})
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	clientStr, err := clientConn.AcceptStream(ctx)
	require.NoError(t, err)
	clientStr.SetReadDeadline(time.Now().Add(time.Second))
	_, err = clientStr.Read([]byte{0})
	require.NoError(t, err)
	clientStr.SetWriteDeadline(time.Time{})
	return clientStr, serverStr
}

func canceledCtx() context.Context {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	return ctx
}

func checkDatagramReceive(t *testing.T, str *stateTrackingStream) {
	t.Helper()
	_, err := str.ReceiveDatagram(canceledCtx())
	require.ErrorIs(t, err, context.Canceled)
}

func checkDatagramSend(t *testing.T, str *stateTrackingStream) {
	t.Helper()
	require.NoError(t, str.SendDatagram([]byte("test")))
}

type mockStreamClearer struct {
	cleared *quic.StreamID
}

func (s *mockStreamClearer) clearStream(id quic.StreamID) {
	s.cleared = &id
}

func TestStateTrackingStreamRead(t *testing.T) {
	t.Run("io.EOF", func(t *testing.T) {
		testStateTrackingStreamRead(t, false)
	})
	t.Run("remote stream reset", func(t *testing.T) {
		testStateTrackingStreamRead(t, true)
	})
}

func testStateTrackingStreamRead(t *testing.T, reset bool) {
	client, server := newStreamPair(t)

	var clearer mockStreamClearer
	str := newStateTrackingStream(client, &clearer, func(b []byte) error { return nil })

	// deadline errors are ignored
	client.SetReadDeadline(time.Now())
	_, err := str.Read(make([]byte, 3))
	require.ErrorIs(t, err, os.ErrDeadlineExceeded)
	require.Nil(t, clearer.cleared)
	client.SetReadDeadline(time.Time{})

	_, err = server.Write([]byte("foobar"))
	require.NoError(t, err)

	if !reset {
		server.Close()

		for range 3 {
			_, err := str.Read([]byte{0})
			require.NoError(t, err)
			require.Nil(t, clearer.cleared)
			checkDatagramReceive(t, str)
		}
	} else {
		server.CancelWrite(42)
	}

	var expectedErr error
	_, err = io.ReadAll(str)
	if !reset {
		require.NoError(t, err)
		expectedErr = io.EOF
	} else {
		expectedErr = &quic.StreamError{Remote: true, StreamID: server.StreamID(), ErrorCode: 42}
		require.ErrorIs(t, err, expectedErr)
	}
	require.Nil(t, clearer.cleared)
	// the receive side registered the error
	_, err = str.ReceiveDatagram(canceledCtx())
	require.ErrorIs(t, err, expectedErr)
	// the send side is still open
	require.NoError(t, str.SendDatagram([]byte("foo")))
}

func TestStateTrackingStreamRemoteCancelation(t *testing.T) {
	client, server := newStreamPair(t)

	var clearer mockStreamClearer
	str := newStateTrackingStream(client, &clearer, func(b []byte) error { return nil })

	_, err := str.Write([]byte("foo"))
	require.NoError(t, err)
	require.Nil(t, clearer.cleared)
	checkDatagramReceive(t, str)
	checkDatagramSend(t, str)

	// deadline errors are ignored
	client.SetWriteDeadline(time.Now())
	_, err = str.Write([]byte("baz"))
	require.ErrorIs(t, err, os.ErrDeadlineExceeded)
	require.Nil(t, clearer.cleared)
	checkDatagramReceive(t, str)
	checkDatagramSend(t, str)
	client.SetWriteDeadline(time.Time{})

	server.CancelRead(123)

	var writeErr error
	require.Eventually(t, func() bool {
		_, writeErr = str.Write([]byte("bar"))
		return writeErr != nil
	}, time.Second, scaleDuration(time.Millisecond))
	expectedErr := &quic.StreamError{Remote: true, StreamID: server.StreamID(), ErrorCode: 123}
	require.ErrorIs(t, writeErr, expectedErr)
	require.Nil(t, clearer.cleared)
	checkDatagramReceive(t, str)
	require.ErrorIs(t, str.SendDatagram([]byte("test")), expectedErr)
}

func TestStateTrackingStreamLocalCancelation(t *testing.T) {
	client, _ := newStreamPair(t)

	var clearer mockStreamClearer
	str := newStateTrackingStream(client, &clearer, func(b []byte) error { return nil })

	_, err := str.Write([]byte("foobar"))
	require.NoError(t, err)
	require.Nil(t, clearer.cleared)
	checkDatagramReceive(t, str)
	checkDatagramSend(t, str)

	str.CancelWrite(1337)
	require.Nil(t, clearer.cleared)
	checkDatagramReceive(t, str)
	require.ErrorIs(t, str.SendDatagram([]byte("test")), &quic.StreamError{StreamID: client.StreamID(), ErrorCode: 1337})
}

func TestStateTrackingStreamClose(t *testing.T) {
	client, _ := newStreamPair(t)

	var clearer mockStreamClearer
	str := newStateTrackingStream(client, &clearer, func(b []byte) error { return nil })

	require.Nil(t, clearer.cleared)
	checkDatagramReceive(t, str)
	checkDatagramSend(t, str)

	require.NoError(t, client.Close())
	require.Eventually(t, func() bool {
		err := str.SendDatagram([]byte("test"))
		if err == nil {
			return false
		}
		require.ErrorIs(t, err, context.Canceled)
		return true
	}, time.Second, scaleDuration(5*time.Millisecond))

	checkDatagramReceive(t, str)
	require.Nil(t, clearer.cleared)
}

func TestStateTrackingStreamReceiveThenSend(t *testing.T) {
	client, server := newStreamPair(t)

	var clearer mockStreamClearer
	str := newStateTrackingStream(client, &clearer, func(b []byte) error { return nil })

	_, err := server.Write([]byte("foobar"))
	require.NoError(t, err)
	require.NoError(t, server.Close())

	_, err = io.ReadAll(str)
	require.NoError(t, err)

	require.Nil(t, clearer.cleared)
	_, err = str.ReceiveDatagram(canceledCtx())
	require.ErrorIs(t, err, io.EOF)

	client.CancelWrite(123)

	id := client.StreamID()
	_, err = str.Write([]byte("bar"))
	require.ErrorIs(t, err, &quic.StreamError{StreamID: id, ErrorCode: 123})
	require.ErrorIs(t, str.SendDatagram([]byte("test")), &quic.StreamError{StreamID: id, ErrorCode: 123})

	require.Equal(t, &id, clearer.cleared)
}

func TestStateTrackingStreamSendThenReceive(t *testing.T) {
	client, server := newStreamPair(t)

	var clearer mockStreamClearer
	str := newStateTrackingStream(client, &clearer, func(b []byte) error { return nil })

	server.CancelRead(1234)

	var writeErr error
	require.Eventually(t, func() bool {
		_, writeErr = str.Write([]byte("bar"))
		return writeErr != nil
	}, time.Second, scaleDuration(time.Millisecond))
	id := server.StreamID()
	expectedErr := &quic.StreamError{Remote: true, StreamID: id, ErrorCode: 1234}
	require.ErrorIs(t, writeErr, expectedErr)
	require.Nil(t, clearer.cleared)
	require.ErrorIs(t, str.SendDatagram([]byte("test")), expectedErr)

	_, err := server.Write([]byte("foobar"))
	require.NoError(t, err)
	require.NoError(t, server.Close())

	_, err = io.ReadAll(str)
	require.NoError(t, err)
	_, err = str.ReceiveDatagram(canceledCtx())
	require.ErrorIs(t, err, io.EOF)

	require.Equal(t, &id, clearer.cleared)
}

func TestDatagramReceiving(t *testing.T) {
	client, _ := newStreamPair(t)

	str := newStateTrackingStream(client, nil, func(b []byte) error { return nil })
	type result struct {
		data []byte
		err  error
	}

	// Receive blocks until a datagram is received
	resultChan := make(chan result)
	go func() {
		defer close(resultChan)
		data, err := str.ReceiveDatagram(context.Background())
		resultChan <- result{data: data, err: err}
	}()

	select {
	case <-time.After(scaleDuration(10 * time.Millisecond)):
	case <-resultChan:
		t.Fatal("should not have received a datagram")
	}
	str.enqueueDatagram([]byte("foobar"))

	select {
	case res := <-resultChan:
		require.NoError(t, res.err)
		require.Equal(t, []byte("foobar"), res.data)
	case <-time.After(time.Second):
		t.Fatal("should have received a datagram")
	}

	// up to 32 datagrams can be queued
	for i := range streamDatagramQueueLen + 1 {
		str.enqueueDatagram([]byte{uint8(i)})
	}
	for i := range streamDatagramQueueLen {
		data, err := str.ReceiveDatagram(context.Background())
		require.NoError(t, err)
		require.Equal(t, []byte{uint8(i)}, data)
	}

	// Receive respects the context
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := str.ReceiveDatagram(ctx)
	require.ErrorIs(t, err, context.Canceled)
}

func TestDatagramSending(t *testing.T) {
	var sendQueue [][]byte
	errors := []error{nil, nil, assert.AnError}
	client, _ := newStreamPair(t)

	str := newStateTrackingStream(client, nil, func(b []byte) error {
		sendQueue = append(sendQueue, b)
		err := errors[0]
		errors = errors[1:]
		return err
	})
	require.NoError(t, str.SendDatagram([]byte("foo")))
	require.NoError(t, str.SendDatagram([]byte("bar")))
	require.ErrorIs(t, str.SendDatagram([]byte("baz")), assert.AnError)
	require.Equal(t, [][]byte{[]byte("foo"), []byte("bar"), []byte("baz")}, sendQueue)

	str.closeSend(net.ErrClosed)
	require.ErrorIs(t, str.SendDatagram([]byte("foobar")), net.ErrClosed)
}
