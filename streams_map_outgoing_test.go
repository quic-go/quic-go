package quic

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"testing"
	"time"

	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/qerr"
	"github.com/quic-go/quic-go/internal/wire"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStreamsMapOutgoingOpenAndDelete(t *testing.T) {
	t.Run("client", func(t *testing.T) {
		testStreamsMapOutgoingOpenAndDelete(t, protocol.PerspectiveClient, protocol.FirstOutgoingBidiStreamClient)
	})
	t.Run("server", func(t *testing.T) {
		testStreamsMapOutgoingOpenAndDelete(t, protocol.PerspectiveServer, protocol.FirstOutgoingBidiStreamServer)
	})
}

func testStreamsMapOutgoingOpenAndDelete(t *testing.T, perspective protocol.Perspective, firstStream protocol.StreamID) {
	m := newOutgoingStreamsMap(
		protocol.StreamTypeBidi,
		func(id protocol.StreamID) *mockStream { return &mockStream{id: id} },
		func(f wire.Frame) {},
		perspective,
	)
	m.SetMaxStream(protocol.MaxStreamID)

	_, err := m.GetStream(firstStream)
	require.ErrorIs(t, err, &qerr.TransportError{ErrorCode: qerr.StreamStateError})
	require.ErrorContains(t, err, fmt.Sprintf("peer attempted to open stream %d", firstStream))

	str1, err := m.OpenStream()
	require.NoError(t, err)
	require.Equal(t, firstStream, str1.id)
	s, err := m.GetStream(firstStream)
	require.NoError(t, err)
	require.Equal(t, s, str1)

	str2, err := m.OpenStream()
	require.NoError(t, err)
	require.Equal(t, firstStream+4, str2.id)

	// update send window
	m.UpdateSendWindow(1000)
	require.Equal(t, protocol.ByteCount(1000), str1.sendWindow)
	require.Equal(t, protocol.ByteCount(1000), str2.sendWindow)

	// enable reset stream at
	m.EnableResetStreamAt()
	require.True(t, str1.supportsResetStreamAt)
	require.True(t, str2.supportsResetStreamAt)

	err = m.DeleteStream(firstStream + 1337*4)
	require.Error(t, err)
	require.ErrorIs(t, err, &qerr.TransportError{ErrorCode: qerr.StreamStateError})
	require.ErrorContains(t, err, "tried to delete unknown outgoing stream")

	require.NoError(t, m.DeleteStream(firstStream))
	// deleting the same stream twice will fail
	err = m.DeleteStream(firstStream)
	require.ErrorIs(t, err, &qerr.TransportError{ErrorCode: qerr.StreamStateError})
	require.ErrorContains(t, err, "tried to delete unknown outgoing stream")
	// after deleting the stream it's not available anymore
	str, err := m.GetStream(firstStream)
	require.NoError(t, err)
	require.Nil(t, str)
}

func TestStreamsMapOutgoingLimits(t *testing.T) {
	t.Run("client", func(t *testing.T) {
		testStreamsMapOutgoingLimits(t, protocol.PerspectiveClient, protocol.FirstOutgoingUniStreamClient)
	})
	t.Run("server", func(t *testing.T) {
		testStreamsMapOutgoingLimits(t, protocol.PerspectiveServer, protocol.FirstOutgoingUniStreamServer)
	})
}

func testStreamsMapOutgoingLimits(t *testing.T, perspective protocol.Perspective, firstStream protocol.StreamID) {
	m := newOutgoingStreamsMap(
		protocol.StreamTypeUni,
		func(id protocol.StreamID) *mockStream { return &mockStream{id: id} },
		func(f wire.Frame) {},
		perspective,
	)
	m.SetMaxStream(firstStream)

	str, err := m.OpenStream()
	require.NoError(t, err)
	require.Equal(t, firstStream, str.id)

	// We've now reached the limit. OpenStream returns an error
	_, err = m.OpenStream()
	require.ErrorIs(t, err, &StreamLimitReachedError{})

	// OpenStreamSync with a canceled context will return an error immediately
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = m.OpenStreamSync(ctx)
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
	var openedStream *mockStream
	go func() {
		str, err := m.OpenStreamSync(context.Background())
		openedStream = str
		errChan <- err
	}()
	m.SetMaxStream(firstStream + 4)
	select {
	case err := <-errChan:
		require.NoError(t, err)
		require.Equal(t, firstStream+4, openedStream.id)
	case <-time.After(time.Second):
		t.Fatal("OpenStreamSync did not return after the stream limit was increased")
	}
}

func TestStreamsMapOutgoingConcurrentOpenStreamSync(t *testing.T) {
	m := newOutgoingStreamsMap(
		protocol.StreamTypeUni,
		func(id protocol.StreamID) *mockStream { return &mockStream{id: id} },
		func(f wire.Frame) {},
		protocol.PerspectiveClient,
	)

	type result struct {
		index  int
		stream *mockStream
		err    error
	}
	results := make(chan result, 3)
	for i := range 3 {
		go func(i int) {
			str, err := m.OpenStreamSync(context.Background())
			results <- result{index: i, stream: str, err: err}
		}(i)
		time.Sleep(scaleDuration(10 * time.Millisecond))
	}

	m.SetMaxStream(protocol.FirstOutgoingUniStreamClient + 4)
	received := make(map[protocol.StreamID]struct{})
	for range 2 {
		select {
		case res := <-results:
			require.NoError(t, res.err)
			require.Equal(t, protocol.FirstOutgoingUniStreamClient+4*protocol.StreamID(res.index), res.stream.id)
			received[res.stream.id] = struct{}{}
		case <-time.After(time.Second):
			t.Fatal("OpenStreamSync did not return after the stream limit was increased")
		}
	}
	require.Contains(t, received, protocol.FirstOutgoingUniStreamClient)
	require.Contains(t, received, protocol.FirstOutgoingUniStreamClient+4)

	// the call to stream 3 is still blocked
	select {
	case <-results:
		t.Fatal("expected OpenStreamSync to be blocked")
	case <-time.After(scaleDuration(10 * time.Millisecond)):
	}
	m.SetMaxStream(protocol.FirstOutgoingUniStreamClient + 8)
	select {
	case res := <-results:
		require.NoError(t, res.err)
		require.Equal(t, protocol.FirstOutgoingUniStreamClient+8, res.stream.id)
	case <-time.After(time.Second):
		t.Fatal("OpenStreamSync did not return after the stream limit was increased")
	}
}

func TestStreamsMapOutgoingClosing(t *testing.T) {
	m := newOutgoingStreamsMap(
		protocol.StreamTypeUni,
		func(id protocol.StreamID) *mockStream { return &mockStream{id: id} },
		func(f wire.Frame) {},
		protocol.PerspectiveServer,
	)

	m.SetMaxStream(protocol.FirstOutgoingUniStreamServer + 4)
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
		func(id protocol.StreamID) *mockStream { return &mockStream{id: id} },
		func(f wire.Frame) { frameQueue = append(frameQueue, f) },
		protocol.PerspectiveClient,
	)

	m.SetMaxStream(protocol.FirstOutgoingBidiStreamClient + 8)
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
	for range 5 {
		_, err = m.OpenStream()
		require.ErrorIs(t, err, &StreamLimitReachedError{})
		require.Empty(t, frameQueue)
	}

	errChan := make(chan error, 3)
	for range 3 {
		go func() {
			_, err := m.OpenStreamSync(context.Background())
			errChan <- err
		}()
	}
	time.Sleep(scaleDuration(10 * time.Millisecond))

	// allow 2 more streams
	m.SetMaxStream(protocol.FirstOutgoingBidiStreamClient + 16)
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
	m.SetMaxStream(protocol.FirstOutgoingBidiStreamClient + 20)
	select {
	case err := <-errChan:
		require.NoError(t, err)
	case <-time.After(time.Second):
		t.Fatal("OpenStreamSync did not return after the stream limit was increased")
	}
	require.Empty(t, frameQueue)
}

func TestStreamsMapOutgoingRandomizedOpenStreamSync(t *testing.T) {
	streamType := []protocol.StreamType{protocol.StreamTypeUni, protocol.StreamTypeBidi}[rand.IntN(2)]
	firstStream := protocol.FirstOutgoingUniStreamServer
	if streamType == protocol.StreamTypeBidi {
		firstStream = protocol.FirstOutgoingBidiStreamServer
	}

	const n = 100

	frameQueue := make(chan wire.Frame, n)
	m := newOutgoingStreamsMap(
		streamType,
		func(id protocol.StreamID) *mockStream { return &mockStream{id: id} },
		func(f wire.Frame) { frameQueue <- f },
		protocol.PerspectiveServer,
	)

	type result struct {
		id  protocol.StreamID
		err error
	}
	resultChan := make(chan result, n)
	for range n {
		go func() {
			str, err := m.OpenStreamSync(context.Background())
			resultChan <- result{id: str.id, err: err}
		}()
	}

	select {
	case f := <-frameQueue:
		require.IsType(t, &wire.StreamsBlockedFrame{}, f)
		require.Zero(t, f.(*wire.StreamsBlockedFrame).StreamLimit)
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for STREAMS_BLOCKED frame")
	}

	limit := firstStream - 4
	var limits []protocol.StreamID
	seen := make(map[protocol.StreamID]struct{})
	maxStream := firstStream + 4*(n-1)
	for limit < maxStream {
		add := 4 * protocol.StreamID(rand.IntN(n/5)+1)
		limit += add
		if limit <= maxStream {
			limits = append(limits, limit)
		}
		t.Logf("setting stream limit to %d", limit)
		m.SetMaxStream(limit)

	loop:
		for {
			select {
			case res := <-resultChan:
				require.NoError(t, res.err)
				require.NotContains(t, seen, res.id)
				require.LessOrEqual(t, res.id, limit)
				seen[res.id] = struct{}{}
				if len(seen) == int(limit.StreamNum()) || len(seen) == n {
					break loop
				}
			case <-time.After(time.Second):
				t.Fatalf("timed out waiting for stream to open")
			}
		}

		str, err := m.OpenStream()
		if limit <= maxStream {
			require.ErrorIs(t, err, &StreamLimitReachedError{})
		} else {
			require.NoError(t, err)
			require.Equal(t, maxStream+4, str.id)
		}
	}
	require.Len(t, seen, n)

	close(frameQueue)
	var blockedAt []protocol.StreamID
	for f := range frameQueue {
		if l := f.(*wire.StreamsBlockedFrame).StreamLimit; l <= n {
			blockedAt = append(blockedAt, l.StreamID(streamType, protocol.PerspectiveServer))
		}
	}
	require.Equal(t, limits, blockedAt)
}

func TestStreamsMapOutgoingRandomizedWithCancellation(t *testing.T) {
	const n = 100

	streamType := []protocol.StreamType{protocol.StreamTypeUni, protocol.StreamTypeBidi}[rand.IntN(2)]
	firstStream := protocol.FirstOutgoingUniStreamClient
	if streamType == protocol.StreamTypeBidi {
		firstStream = protocol.FirstOutgoingBidiStreamClient
	}

	frameQueue := make(chan wire.Frame, n)
	m := newOutgoingStreamsMap(
		streamType,
		func(id protocol.StreamID) *mockStream { return &mockStream{id: id} },
		func(f wire.Frame) { frameQueue <- f },
		protocol.PerspectiveClient,
	)

	type result struct {
		str *mockStream
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
			var str *mockStream
			var err error
			if shouldCancel {
				str, err = m.OpenStreamSync(ctx)
			} else {
				str, err = m.OpenStreamSync(context.Background())
			}
			resultChan <- result{str: str, err: err}
		}()
	}

	select {
	case f := <-frameQueue:
		require.IsType(t, &wire.StreamsBlockedFrame{}, f)
		require.Zero(t, f.(*wire.StreamsBlockedFrame).StreamLimit)
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for STREAMS_BLOCKED frame")
	}

	time.Sleep(scaleDuration(10 * time.Millisecond))
	cancel()

	limit := firstStream - 4
	maxStream := firstStream + 4*(n-1)
	var limits []protocol.StreamID
	seen := make(map[protocol.StreamID]struct{})
	var lastStreamSeen protocol.StreamID
	var numCancelledSeen int
	for limit < maxStream {
		add := 4 * protocol.StreamID(rand.IntN(n/5)+1)
		limit += add
		if limit < maxStream {
			limits = append(limits, limit)
		}
		t.Logf("setting stream limit to %d", limit)
		m.SetMaxStream(limit)

		for lastStreamSeen < min(maxStream, limit) {
			select {
			case res := <-resultChan:
				if errors.Is(res.err, context.Canceled) {
					numCancelledSeen++
				} else {
					require.NoError(t, res.err)
					require.NotContains(t, seen, res.str.id)
					seen[res.str.id] = struct{}{}
					lastStreamSeen = res.str.id
				}
			case <-time.After(time.Second):
				t.Fatalf("timed out waiting for stream to open")
			}
		}
	}
	require.Len(t, seen, n)
	require.Equal(t, numCancelled, numCancelledSeen)

	close(frameQueue)
	var blockedAt []protocol.StreamID
	for f := range frameQueue {
		sbf := f.(*wire.StreamsBlockedFrame)
		require.Equal(t, streamType, sbf.Type)
		blockedAt = append(blockedAt, sbf.StreamLimit.StreamID(streamType, protocol.PerspectiveClient))
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
		func(id protocol.StreamID) *mockStream { return &mockStream{id: id} },
		func(f wire.Frame) {},
		protocol.PerspectiveClient,
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
	go m.SetMaxStream(protocol.FirstOutgoingBidiStreamClient + 4*num/2)

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
