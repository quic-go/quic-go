package quic

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/wire"
	"github.com/stretchr/testify/require"
)

type mockGenericStream struct {
	num protocol.StreamNum

	closed     bool
	closeErr   error
	sendWindow protocol.ByteCount
}

func (s *mockGenericStream) closeForShutdown(err error) {
	s.closed = true
	s.closeErr = err
}

func (s *mockGenericStream) updateSendWindow(limit protocol.ByteCount) {
	s.sendWindow = limit
}

func TestIncomingStreamsMapGettingStreams(t *testing.T) {
	var newItemCounter int
	const maxNumStreams = 10
	m := newIncomingStreamsMap(
		protocol.StreamTypeUni,
		func(num protocol.StreamNum) *mockGenericStream {
			newItemCounter++
			return &mockGenericStream{num: num}
		},
		maxNumStreams,
		func(f wire.Frame) {},
	)

	// all streams up to the id on GetOrOpenStream are opened
	str, err := m.GetOrOpenStream(2)
	require.NoError(t, err)
	require.Equal(t, 2, newItemCounter)
	require.Equal(t, protocol.StreamNum(2), str.num)
	// accept one of the streams
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	str, err = m.AcceptStream(ctx)
	require.NoError(t, err)
	require.Equal(t, protocol.StreamNum(1), str.num)
	// open some more streams
	str, err = m.GetOrOpenStream(5)
	require.NoError(t, err)
	require.Equal(t, 5, newItemCounter)
	require.Equal(t, protocol.StreamNum(5), str.num)
	// and accept all of them
	for i := 2; i <= 5; i++ {
		str, err := m.AcceptStream(ctx)
		require.NoError(t, err)
		require.Equal(t, protocol.StreamNum(i), str.num)
	}

	_, err = m.GetOrOpenStream(maxNumStreams)
	require.NoError(t, err)
	_, err = m.GetOrOpenStream(maxNumStreams + 1)
	require.Error(t, err)
	require.ErrorContains(t, err, "peer tried to open stream")
}

func TestIncomingStreamsMapAcceptingStreams(t *testing.T) {
	m := newIncomingStreamsMap(
		protocol.StreamTypeUni,
		func(num protocol.StreamNum) *mockGenericStream { return &mockGenericStream{num: num} },
		5,
		func(f wire.Frame) {},
	)

	errChan := make(chan error, 1)

	// AcceptStream should respect the context
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), scaleDuration(10*time.Millisecond))
		defer cancel()
		_, err := m.AcceptStream(ctx)
		errChan <- err
	}()

	select {
	case err := <-errChan:
		require.Equal(t, context.DeadlineExceeded, err)
	case <-time.After(time.Second):
		t.Fatal("timeout")
	}

	// AcceptStream should block if there are no streams available
	go func() {
		_, err := m.AcceptStream(context.Background())
		errChan <- err
	}()

	select {
	case <-errChan:
		t.Fatal("AcceptStream should block")
	case <-time.After(scaleDuration(10 * time.Millisecond)):
	}

	_, err := m.GetOrOpenStream(1)
	require.NoError(t, err)

	select {
	case err := <-errChan:
		require.NoError(t, err)
	case <-time.After(time.Second):
		t.Fatal("timeout")
	}
}

func TestIncomingStreamsMapDeletingStreams(t *testing.T) {
	m := newIncomingStreamsMap(
		protocol.StreamTypeUni,
		func(num protocol.StreamNum) *mockGenericStream { return &mockGenericStream{num: num} },
		5,
		func(f wire.Frame) {},
	)
	_ = m
}

func TestIncomingStreamsMapClosing(t *testing.T) {
	m := newIncomingStreamsMap(
		protocol.StreamTypeUni,
		func(num protocol.StreamNum) *mockGenericStream { return &mockGenericStream{num: num} },
		5,
		func(f wire.Frame) {},
	)

	var streams []*mockGenericStream
	_, err := m.GetOrOpenStream(3)
	require.NoError(t, err)
	for range 3 {
		str, err := m.AcceptStream(context.Background())
		require.NoError(t, err)
		streams = append(streams, str)
	}

	errChan := make(chan error, 1)
	go func() {
		_, err := m.AcceptStream(context.Background())
		errChan <- err
	}()

	testErr := errors.New("test error")
	m.CloseWithError(testErr)

	// accepted streams should be closed
	for _, str := range streams {
		require.True(t, str.closed)
		require.ErrorIs(t, str.closeErr, testErr)
	}
	// AcceptStream should return the error
	select {
	case err := <-errChan:
		require.ErrorIs(t, err, testErr)
	case <-time.After(time.Second):
		t.Fatal("timeout")
	}
}
