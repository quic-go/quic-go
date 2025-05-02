package quic

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"testing"
	"time"

	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/wire"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStreamsMapOutgoingOpenAndDelete(t *testing.T) {
	m := newOutgoingStreamsMap(
		protocol.StreamTypeBidi,
		func(n protocol.StreamNum) *mockGenericStream { return &mockGenericStream{num: n} },
		func(f wire.Frame) {},
	)
	m.SetMaxStream(protocol.MaxStreamCount)

	_, err := m.GetStream(1)
	require.Error(t, err)
	require.ErrorContains(t, err.(streamError).TestError(), "peer attempted to open stream 1")

	str1, err := m.OpenStream()
	require.NoError(t, err)
	require.Equal(t, protocol.StreamNum(1), str1.num)
	s, err := m.GetStream(1)
	require.NoError(t, err)
	require.Equal(t, s, str1)

	str2, err := m.OpenStream()
	require.NoError(t, err)
	require.Equal(t, protocol.StreamNum(2), str2.num)

	// update send window
	m.UpdateSendWindow(1000)
	require.Equal(t, protocol.ByteCount(1000), str1.sendWindow)
	require.Equal(t, protocol.ByteCount(1000), str2.sendWindow)

	err = m.DeleteStream(1337)
	require.Error(t, err)
	require.ErrorContains(t, err.(streamError).TestError(), "tried to delete unknown outgoing stream 1337")

	require.NoError(t, m.DeleteStream(1))
	// deleting the same stream twice will fail
	err = m.DeleteStream(1)
	require.Error(t, err)
	require.ErrorContains(t, err.(streamError).TestError(), "tried to delete unknown outgoing stream 1")
	// after deleting the stream it's not available anymore
	str, err := m.GetStream(1)
	require.NoError(t, err)
	require.Nil(t, str)
}

func TestStreamsMapOutgoingLimits(t *testing.T) {
	m := newOutgoingStreamsMap(
		protocol.StreamTypeBidi,
		func(n protocol.StreamNum) *mockGenericStream { return &mockGenericStream{num: n} },
		func(f wire.Frame) {},
	)
	m.SetMaxStream(1)

	str, err := m.OpenStream()
	require.NoError(t, err)
	require.Equal(t, protocol.StreamNum(1), str.num)

	// We've now reached the limit. OpenStream returns an error
	_, err = m.OpenStream()
	require.ErrorIs(t, err, &StreamLimitReachedError{})

	// OpenStreamSync with a canceled context will return an error immediately
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = m.OpenStreamSync(ctx)
	require.Error(t, err)
	require.ErrorIs(t, err, context.Canceled)

	// OpenStreamSync blocks until the context is canceled...
	ctx, cancel = context.WithCancel(context.Background())
	errChan := make(chan error, 1)
	go func() {
		_, err := m.OpenStreamSync(ctx)
		errChan <- err
	}()

	select {
	case <-errChan:
		t.Fatal("didn't expect OpenStreamSync to return")
	case <-time.After(scaleDuration(10 * time.Millisecond)):
	}
	// OpenStream still returns an error
	_, err = m.OpenStream()
	require.ErrorIs(t, err, &StreamLimitReachedError{})
	// cancelling the context unblocks OpenStreamSync
	cancel()
	select {
	case err := <-errChan:
		require.ErrorIs(t, err, context.Canceled)
	case <-time.After(time.Second):
		t.Fatal("OpenStreamSync did not return after the context was canceled")
	}

	// ... or until it's possible to open a new stream
	var openedStream *mockGenericStream
	go func() {
		str, err := m.OpenStreamSync(context.Background())
		openedStream = str
		errChan <- err
	}()
	m.SetMaxStream(2)
	select {
	case err := <-errChan:
		require.NoError(t, err)
		require.Equal(t, protocol.StreamNum(2), openedStream.num)
	case <-time.After(time.Second):
		t.Fatal("OpenStreamSync did not return after the stream limit was increased")
	}
}

func TestStreamsMapOutgoingConcurrentOpenStreamSync(t *testing.T) {
	m := newOutgoingStreamsMap(
		protocol.StreamTypeBidi,
		func(n protocol.StreamNum) *mockGenericStream { return &mockGenericStream{num: n} },
		func(f wire.Frame) {},
	)

	type result struct {
		index  int
		stream *mockGenericStream
		err    error
	}

	results := make(chan result, 3)
	for i := range 3 {
		go func(i int) {
			str, err := m.OpenStreamSync(context.Background())
			results <- result{index: i + 1, stream: str, err: err}
		}(i)
		time.Sleep(scaleDuration(10 * time.Millisecond))
	}

	m.SetMaxStream(2)
	received := make(map[protocol.StreamNum]struct{})
	for range 2 {
		select {
		case res := <-results:
			require.NoError(t, res.err)
			require.Equal(t, res.index, int(res.stream.num))
			received[res.stream.num] = struct{}{}
		case <-time.After(time.Second):
			t.Fatal("OpenStreamSync did not return after the stream limit was increased")
		}
	}
	require.Contains(t, received, protocol.StreamNum(1))
	require.Contains(t, received, protocol.StreamNum(2))

	// the call to stream 3 is still blocked
	select {
	case <-results:
		t.Fatal("expected OpenStreamSync to be blocked")
	case <-time.After(scaleDuration(10 * time.Millisecond)):
	}
	m.SetMaxStream(3)
	select {
	case res := <-results:
		require.NoError(t, res.err)
		require.Equal(t, protocol.StreamNum(3), res.stream.num)
	case <-time.After(time.Second):
		t.Fatal("OpenStreamSync did not return after the stream limit was increased")
	}
}

func TestStreamsMapOutgoingClosing(t *testing.T) {
	m := newOutgoingStreamsMap(
		protocol.StreamTypeBidi,
		func(n protocol.StreamNum) *mockGenericStream { return &mockGenericStream{num: n} },
		func(f wire.Frame) {},
	)

	m.SetMaxStream(2)
	str1, err := m.OpenStream()
	require.NoError(t, err)
	str2, err := m.OpenStream()
	require.NoError(t, err)

	errChan := make(chan error, 1)
	go func() {
		_, err := m.OpenStreamSync(context.Background())
		errChan <- err
	}()

	m.CloseWithError(assert.AnError)
	// both stream should be closed
	assert.True(t, str1.closed)
	assert.Equal(t, assert.AnError, str1.closeErr)
	assert.True(t, str2.closed)
	assert.Equal(t, assert.AnError, str2.closeErr)

	select {
	case err := <-errChan:
		require.Error(t, err)
	case <-time.After(time.Second):
		t.Fatal("OpenStreamSync did not return after the stream was closed")
	}
}

func TestStreamsMapOutgoingBlockedFrames(t *testing.T) {
	var frameQueue []wire.Frame
	m := newOutgoingStreamsMap(
		protocol.StreamTypeBidi,
		func(n protocol.StreamNum) *mockGenericStream { return &mockGenericStream{num: n} },
		func(f wire.Frame) { frameQueue = append(frameQueue, f) },
	)

	m.SetMaxStream(3)
	for range 3 {
		_, err := m.OpenStream()
		require.NoError(t, err)
	}
	require.Empty(t, frameQueue)

	_, err := m.OpenStream()
	require.ErrorIs(t, err, &StreamLimitReachedError{})
	require.Equal(t, []wire.Frame{
		&wire.StreamsBlockedFrame{Type: protocol.StreamTypeBidi, StreamLimit: 3},
	}, frameQueue)
	frameQueue = frameQueue[:0]

	// only a single STREAMS_BLOCKED frame is queued per offset
	_, err = m.OpenStream()
	require.ErrorIs(t, err, &StreamLimitReachedError{})
	require.Empty(t, frameQueue)

	errChan := make(chan error, 3)
	for range 3 {
		go func() {
			_, err := m.OpenStreamSync(context.Background())
			errChan <- err
		}()
	}
	time.Sleep(scaleDuration(10 * time.Millisecond))

	// allow 2 more streams
	m.SetMaxStream(5)
	for range 2 {
		select {
		case err := <-errChan:
			require.NoError(t, err)
		case <-time.After(time.Second):
			t.Fatal("OpenStreamSync did not return after the stream limit was increased")
		}
	}
	require.Equal(t, []wire.Frame{
		&wire.StreamsBlockedFrame{Type: protocol.StreamTypeBidi, StreamLimit: 5},
	}, frameQueue)
	frameQueue = frameQueue[:0]

	// now accept the last stream
	m.SetMaxStream(6)
	select {
	case err := <-errChan:
		require.NoError(t, err)
	case <-time.After(time.Second):
		t.Fatal("OpenStreamSync did not return after the stream limit was increased")
	}
	require.Empty(t, frameQueue)
}

func TestStreamsMapOutgoingRandomizedOpenStreamSync(t *testing.T) {
	const n = 100

	frameQueue := make(chan wire.Frame, n)
	m := newOutgoingStreamsMap(
		protocol.StreamTypeBidi,
		func(n protocol.StreamNum) *mockGenericStream { return &mockGenericStream{num: n} },
		func(f wire.Frame) { frameQueue <- f },
	)

	type result struct {
		num protocol.StreamNum
		err error
	}

	resultChan := make(chan result, n)
	for range n {
		go func() {
			str, err := m.OpenStreamSync(context.Background())
			resultChan <- result{num: str.num, err: err}
		}()
	}

	select {
	case f := <-frameQueue:
		require.IsType(t, &wire.StreamsBlockedFrame{}, f)
		require.Zero(t, f.(*wire.StreamsBlockedFrame).StreamLimit)
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for STREAMS_BLOCKED frame")
	}

	var limit int
	var limits []protocol.StreamNum
	seen := make(map[protocol.StreamNum]struct{})
	for limit < n {
		add := rand.IntN(n/5) + 1
		limit += add
		if limit <= n {
			limits = append(limits, protocol.StreamNum(limit))
		}
		t.Logf("setting stream limit to %d", limit)
		m.SetMaxStream(protocol.StreamNum(limit))

		for range min(add, n-(limit-add)) {
			select {
			case res := <-resultChan:
				require.NoError(t, res.err)
				require.NotContains(t, seen, res.num)
				seen[res.num] = struct{}{}
			case <-time.After(time.Second):
				t.Fatalf("timed out waiting for stream to open")
			}
		}

		str, err := m.OpenStream()
		if limit <= n {
			require.ErrorIs(t, err, &StreamLimitReachedError{})
		} else {
			require.NoError(t, err)
			require.Equal(t, protocol.StreamNum(n+1), str.num)
		}
	}
	require.Len(t, seen, n)

	var blockedAt []protocol.StreamNum
	close(frameQueue)
	for f := range frameQueue {
		if l := f.(*wire.StreamsBlockedFrame).StreamLimit; l <= n {
			blockedAt = append(blockedAt, l)
		}
	}
	require.Equal(t, limits, blockedAt)
}

func TestStreamsMapOutgoingRandomizedWithCancellation(t *testing.T) {
	const n = 100

	var frameQueue []wire.Frame
	m := newOutgoingStreamsMap(
		protocol.StreamTypeBidi,
		func(n protocol.StreamNum) *mockGenericStream { return &mockGenericStream{num: n} },
		func(f wire.Frame) { frameQueue = append(frameQueue, f) },
	)

	type result struct {
		str *mockGenericStream
		err error
	}

	ctx, cancel := context.WithCancel(context.Background())
	resultChan := make(chan result, 10*n)
	var count int
	var numCancelled int
	for count < n {
		shouldCancel := rand.IntN(n)%5 == 0
		if shouldCancel {
			numCancelled++
		} else {
			count++
		}
		go func() {
			var str *mockGenericStream
			var err error
			if shouldCancel {
				str, err = m.OpenStreamSync(ctx)
			} else {
				str, err = m.OpenStreamSync(context.Background())
			}
			resultChan <- result{str: str, err: err}
		}()
	}

	time.Sleep(scaleDuration(10 * time.Millisecond))
	cancel()

	var limit int
	limits := []protocol.StreamNum{0}
	seen := make(map[protocol.StreamNum]struct{})
	var lastStreamSeen protocol.StreamNum
	var numCancelledSeen int
	for limit < n {
		limit += rand.IntN(n/5) + 1
		if limit < n {
			limits = append(limits, protocol.StreamNum(limit))
		}
		t.Logf("setting stream limit to %d", limit)
		m.SetMaxStream(protocol.StreamNum(limit))

		for lastStreamSeen < min(n, protocol.StreamNum(limit)) {
			select {
			case res := <-resultChan:
				if errors.Is(res.err, context.Canceled) {
					numCancelledSeen++
				} else {
					require.NoError(t, res.err)
					require.NotContains(t, seen, res.str.num)
					seen[res.str.num] = struct{}{}
					lastStreamSeen = res.str.num
				}
			case <-time.After(time.Second):
				t.Fatalf("timed out waiting for stream to open")
			}
		}
	}
	require.Len(t, seen, n)
	require.Equal(t, numCancelled, numCancelledSeen)

	var blockedAt []protocol.StreamNum
	for _, f := range frameQueue {
		blockedAt = append(blockedAt, f.(*wire.StreamsBlockedFrame).StreamLimit)
	}
	require.Equal(t, limits, blockedAt)
}

func TestStreamsMapConcurrent(t *testing.T) {
	for i := range 5 {
		t.Run(fmt.Sprintf("iteration %d", i+1), func(t *testing.T) {
			testStreamsMapConcurrent(t)
		})
	}
}

func testStreamsMapConcurrent(t *testing.T) {
	m := newOutgoingStreamsMap(
		protocol.StreamTypeBidi,
		func(n protocol.StreamNum) *mockGenericStream { return &mockGenericStream{num: n} },
		func(f wire.Frame) {},
	)

	const num = 100

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errChan := make(chan error, num)
	for range num {
		go func() {
			_, err := m.OpenStreamSync(ctx)
			errChan <- err
		}()
	}

	time.Sleep(scaleDuration(5 * time.Millisecond))
	go m.CloseWithError(assert.AnError)
	go cancel()
	go m.SetMaxStream(protocol.StreamNum(num / 2))

	for range num {
		select {
		case err := <-errChan:
			if err != nil {
				require.True(t, errors.Is(err, assert.AnError) || errors.Is(err, context.Canceled))
			}
		case <-time.After(time.Second):
			t.Fatal("timed out waiting for error")
		}
	}
}
