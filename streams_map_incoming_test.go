package quic

import (
	"context"
	"errors"
	"math/rand/v2"
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

func TestStreamsMapIncomingGettingStreams(t *testing.T) {
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

func TestStreamsMapIncomingAcceptingStreams(t *testing.T) {
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

func TestStreamsMapIncomingDeletingStreams(t *testing.T) {
	var frameQueue []wire.Frame
	m := newIncomingStreamsMap(
		protocol.StreamTypeUni,
		func(num protocol.StreamNum) *mockGenericStream { return &mockGenericStream{num: num} },
		5,
		func(f wire.Frame) { frameQueue = append(frameQueue, f) },
	)
	err := m.DeleteStream(1337)
	require.Error(t, err)
	require.ErrorContains(t, err.(streamError).TestError(), "tried to delete unknown incoming stream 1337")

	s, err := m.GetOrOpenStream(2)
	require.NoError(t, err)
	require.NotNil(t, s)
	// delete the stream
	require.NoError(t, m.DeleteStream(2))
	require.Empty(t, frameQueue)
	// it's not returned by GetOrOpenStream anymore
	s, err = m.GetOrOpenStream(2)
	require.NoError(t, err)
	require.Nil(t, s)

	// AcceptStream still returns this stream
	str, err := m.AcceptStream(context.Background())
	require.NoError(t, err)
	require.Equal(t, protocol.StreamNum(1), str.num)
	require.Empty(t, frameQueue)

	str, err = m.AcceptStream(context.Background())
	require.NoError(t, err)
	require.Equal(t, protocol.StreamNum(2), str.num)
	// now the stream is deleted and new stream credit is issued
	require.Len(t, frameQueue, 1)
	require.Equal(t, &wire.MaxStreamsFrame{Type: protocol.StreamTypeUni, MaxStreamNum: 6}, frameQueue[0])
	frameQueue = frameQueue[:0]

	require.NoError(t, m.DeleteStream(1))
	require.Len(t, frameQueue, 1)
	require.Equal(t, &wire.MaxStreamsFrame{Type: protocol.StreamTypeUni, MaxStreamNum: 7}, frameQueue[0])
}

// There's a maximum number that can be encoded in a MAX_STREAMS frame.
// Since the stream limit is configurable by the user, we can't rely on this number
// being high enough that it will never be reached in practice.
func TestStreamsMapIncomingDeletingStreamsWithHighLimits(t *testing.T) {
	var frameQueue []wire.Frame
	m := newIncomingStreamsMap(
		protocol.StreamTypeUni,
		func(num protocol.StreamNum) *mockGenericStream { return &mockGenericStream{num: num} },
		uint64(protocol.MaxStreamCount-2),
		func(f wire.Frame) { frameQueue = append(frameQueue, f) },
	)

	// open a bunch of streams
	_, err := m.GetOrOpenStream(5)
	require.NoError(t, err)
	// accept all streams
	for i := 0; i < 5; i++ {
		_, err := m.AcceptStream(context.Background())
		require.NoError(t, err)
	}
	require.Empty(t, frameQueue)
	require.NoError(t, m.DeleteStream(4))
	require.Len(t, frameQueue, 1)
	require.Equal(t, &wire.MaxStreamsFrame{Type: protocol.StreamTypeUni, MaxStreamNum: protocol.MaxStreamCount - 1}, frameQueue[0])
	require.NoError(t, m.DeleteStream(3))
	require.Len(t, frameQueue, 2)
	require.Equal(t, &wire.MaxStreamsFrame{Type: protocol.StreamTypeUni, MaxStreamNum: protocol.MaxStreamCount}, frameQueue[1])
	// at this point, we can't increase the stream limit any further, so no more MAX_STREAMS frames will be sent
	require.NoError(t, m.DeleteStream(2))
	require.NoError(t, m.DeleteStream(1))
	require.Len(t, frameQueue, 2)
}

func TestStreamsMapIncomingClosing(t *testing.T) {
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

func TestStreamsMapIncomingRandomized(t *testing.T) {
	const num = 1000

	m := newIncomingStreamsMap(
		protocol.StreamTypeUni,
		func(num protocol.StreamNum) *mockGenericStream { return &mockGenericStream{num: num} },
		num,
		func(f wire.Frame) {},
	)

	ids := make([]protocol.StreamNum, num)
	for i := range num {
		ids[i] = protocol.StreamNum(i + 1)
	}
	rand.Shuffle(len(ids), func(i, j int) { ids[i], ids[j] = ids[j], ids[i] })

	timeout := scaleDuration(time.Second)
	errChan1 := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		for range num {
			if _, err := m.AcceptStream(ctx); err != nil {
				errChan1 <- err
				return
			}
		}
		close(errChan1)
	}()

	errChan2 := make(chan error, 1)
	go func() {
		for i := range num {
			_, err := m.GetOrOpenStream(ids[i])
			if err != nil {
				errChan2 <- err
				return
			}
		}
		close(errChan2)
	}()

	select {
	case err := <-errChan1:
		require.NoError(t, err)
	case <-time.After(timeout * 3 / 2):
		t.Fatal("timeout")
	}
	select {
	case err := <-errChan2:
		require.NoError(t, err)
	case <-time.After(timeout * 3 / 2):
		t.Fatal("timeout")
	}
}
