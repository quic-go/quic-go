package quic

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/quic-go/quic-go/internal/utils"
	"github.com/quic-go/quic-go/internal/wire"

	"github.com/stretchr/testify/require"
)

func TestDatagramQueuePeekAndPop(t *testing.T) {
	var queued []struct{}
	queue := newDatagramQueue(func() { queued = append(queued, struct{}{}) }, utils.DefaultLogger)
	require.Nil(t, queue.Peek())
	require.Empty(t, queued)
	require.NoError(t, queue.Add(&wire.DatagramFrame{Data: []byte("foo")}))
	require.Len(t, queued, 1)
	require.Equal(t, &wire.DatagramFrame{Data: []byte("foo")}, queue.Peek())
	// calling peek again returns the same datagram
	require.Equal(t, &wire.DatagramFrame{Data: []byte("foo")}, queue.Peek())
	queue.Pop()
	require.Nil(t, queue.Peek())
}

func TestDatagramQueueSendQueueLength(t *testing.T) {
	queue := newDatagramQueue(func() {}, utils.DefaultLogger)

	for i := 0; i < maxDatagramSendQueueLen; i++ {
		require.NoError(t, queue.Add(&wire.DatagramFrame{Data: []byte{0}}))
	}
	errChan := make(chan error, 1)
	go func() { errChan <- queue.Add(&wire.DatagramFrame{Data: []byte("foobar")}) }()

	select {
	case <-errChan:
		t.Fatal("expected to not receive error")
	case <-time.After(scaleDuration(10 * time.Millisecond)):
	}

	// peeking doesn't remove the datagram from the queue...
	require.NotNil(t, queue.Peek())
	select {
	case <-errChan:
		t.Fatal("expected to not receive error")
	case <-time.After(scaleDuration(10 * time.Millisecond)):
	}

	// ...but popping does
	queue.Pop()
	select {
	case err := <-errChan:
		require.NoError(t, err)
	case <-time.After(time.Second):
		t.Fatal("timeout")
	}
	// pop all the remaining datagrams
	for i := 1; i < maxDatagramSendQueueLen; i++ {
		queue.Pop()
	}
	f := queue.Peek()
	require.NotNil(t, f)
	require.Equal(t, &wire.DatagramFrame{Data: []byte("foobar")}, f)
}

func TestDatagramQueueReceive(t *testing.T) {
	queue := newDatagramQueue(func() {}, utils.DefaultLogger)

	// receive frames that were received earlier
	queue.HandleDatagramFrame(&wire.DatagramFrame{Data: []byte("foo")})
	queue.HandleDatagramFrame(&wire.DatagramFrame{Data: []byte("bar")})
	data, err := queue.Receive(context.Background())
	require.NoError(t, err)
	require.Equal(t, []byte("foo"), data)
	data, err = queue.Receive(context.Background())
	require.NoError(t, err)
	require.Equal(t, []byte("bar"), data)
}

func TestDatagramQueueReceiveBlocking(t *testing.T) {
	queue := newDatagramQueue(func() {}, utils.DefaultLogger)

	// block until a new frame is received
	type result struct {
		data []byte
		err  error
	}
	resultChan := make(chan result, 1)
	go func() {
		data, err := queue.Receive(context.Background())
		resultChan <- result{data, err}
	}()

	select {
	case <-resultChan:
		t.Fatal("expected to not receive result")
	case <-time.After(scaleDuration(10 * time.Millisecond)):
	}
	queue.HandleDatagramFrame(&wire.DatagramFrame{Data: []byte("foobar")})
	select {
	case result := <-resultChan:
		require.NoError(t, result.err)
		require.Equal(t, []byte("foobar"), result.data)
	case <-time.After(time.Second):
		t.Fatal("timeout")
	}

	// unblock when the context is canceled
	ctx, cancel := context.WithCancel(context.Background())
	errChan := make(chan error, 1)
	go func() {
		_, err := queue.Receive(ctx)
		errChan <- err
	}()
	select {
	case <-errChan:
		t.Fatal("expected to not receive error")
	case <-time.After(scaleDuration(10 * time.Millisecond)):
	}
	cancel()
	select {
	case err := <-errChan:
		require.ErrorIs(t, err, context.Canceled)
	case <-time.After(time.Second):
		t.Fatal("timeout")
	}
}

func TestDatagramQueueClose(t *testing.T) {
	queue := newDatagramQueue(func() {}, utils.DefaultLogger)

	for i := 0; i < maxDatagramSendQueueLen; i++ {
		require.NoError(t, queue.Add(&wire.DatagramFrame{Data: []byte{0}}))
	}
	errChan1 := make(chan error, 1)
	go func() { errChan1 <- queue.Add(&wire.DatagramFrame{Data: []byte("foobar")}) }()
	errChan2 := make(chan error, 1)
	go func() {
		_, err := queue.Receive(context.Background())
		errChan2 <- err
	}()

	queue.CloseWithError(errors.New("test error"))

	select {
	case err := <-errChan1:
		require.EqualError(t, err, "test error")
	case <-time.After(time.Second):
		t.Fatal("timeout")
	}

	select {
	case err := <-errChan2:
		require.EqualError(t, err, "test error")
	case <-time.After(time.Second):
		t.Fatal("timeout")
	}
}
