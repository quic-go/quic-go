package http3

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDatagramReceiving(t *testing.T) {
	dg := newDatagrammer(nil)

	type result struct {
		data []byte
		err  error
	}

	// Receive blocks until a datagram is received
	resultChan := make(chan result)
	go func() {
		defer close(resultChan)
		data, err := dg.Receive(context.Background())
		resultChan <- result{data: data, err: err}
	}()

	select {
	case <-time.After(scaleDuration(10 * time.Millisecond)):
	case <-resultChan:
		t.Fatal("should not have received a datagram")
	}
	dg.enqueue([]byte("foobar"))

	select {
	case res := <-resultChan:
		require.NoError(t, res.err)
		require.Equal(t, []byte("foobar"), res.data)
	case <-time.After(time.Second):
		t.Fatal("should have received a datagram")
	}

	// up to 32 datagrams can be queued
	for i := range streamDatagramQueueLen + 1 {
		dg.enqueue([]byte{uint8(i)})
	}
	for i := range streamDatagramQueueLen {
		data, err := dg.Receive(context.Background())
		require.NoError(t, err)
		require.Equal(t, []byte{uint8(i)}, data)
	}

	// Receive respects the context
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := dg.Receive(ctx)
	require.ErrorIs(t, err, context.Canceled)
}

func TestDatagramReceiveError(t *testing.T) {
	dg := newDatagrammer(nil)

	errChan := make(chan error)
	go func() {
		_, err := dg.Receive(context.Background())
		errChan <- err
	}()

	select {
	case <-time.After(scaleDuration(10 * time.Millisecond)):
	case err := <-errChan:
		t.Fatalf("should not have received an error: %v", err)
	}

	dg.SetReceiveError(assert.AnError)
	select {
	case err := <-errChan:
		require.ErrorIs(t, err, assert.AnError)
	case <-time.After(time.Second):
		t.Fatal("timeout")
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_, err := dg.Receive(ctx)
	require.ErrorIs(t, err, assert.AnError)
}

func TestDatagramSending(t *testing.T) {
	var sendQueue [][]byte
	errors := []error{nil, nil, assert.AnError}
	dg := newDatagrammer(func(b []byte) error {
		sendQueue = append(sendQueue, b)
		err := errors[0]
		errors = errors[1:]
		return err
	})
	require.NoError(t, dg.Send([]byte("foo")))
	require.NoError(t, dg.Send([]byte("bar")))
	require.ErrorIs(t, dg.Send([]byte("baz")), assert.AnError)
	require.Equal(t, [][]byte{[]byte("foo"), []byte("bar"), []byte("baz")}, sendQueue)

	dg.SetSendError(net.ErrClosed)
	require.ErrorIs(t, dg.Send([]byte("foobar")), net.ErrClosed)
}
