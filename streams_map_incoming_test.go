package quic

import (
	"context"
	"math/rand/v2"
	"testing"
	"time"

	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/qerr"
	"github.com/quic-go/quic-go/internal/wire"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockStream struct {
	id protocol.StreamID

	closed                bool
	closeErr              error
	sendWindow            protocol.ByteCount
	supportsResetStreamAt bool
}

func (s *mockStream) closeForShutdown(err error) {
	s.closed = true
	s.closeErr = err
}

func (s *mockStream) updateSendWindow(limit protocol.ByteCount) {
	s.sendWindow = limit
}

func (s *mockStream) enableResetStreamAt() {
	s.supportsResetStreamAt = true
}

func TestStreamsMapIncomingGettingStreams(t *testing.T) {
	t.Run("client", func(t *testing.T) {
		testStreamsMapIncomingGettingStreams(t, protocol.PerspectiveClient, protocol.FirstIncomingUniStreamClient)
	})
	t.Run("server", func(t *testing.T) {
		testStreamsMapIncomingGettingStreams(t, protocol.PerspectiveServer, protocol.FirstIncomingUniStreamServer)
	})
}

func testStreamsMapIncomingGettingStreams(t *testing.T, perspective protocol.Perspective, firstStream protocol.StreamID) {
	var newStreamCounter int
	const maxNumStreams = 10
	m := newIncomingStreamsMap(
		protocol.StreamTypeUni,
		func(id protocol.StreamID) *mockStream {
			newStreamCounter++
			return &mockStream{id: id}
		},
		maxNumStreams,
		func(f wire.Frame) {},
		perspective,
	)

	// all streams up to the id on GetOrOpenStream are opened
	str, err := m.GetOrOpenStream(firstStream + 4)
	require.NoError(t, err)
	require.NotNil(t, str)
	require.Equal(t, 2, newStreamCounter)
	require.Equal(t, firstStream+4, str.id)
	// accept one of the streams
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	str, err = m.AcceptStream(ctx)
	require.NoError(t, err)
	require.Equal(t, firstStream, str.id)
	// open some more streams
	str, err = m.GetOrOpenStream(firstStream + 16)
	require.NoError(t, err)
	require.Equal(t, 5, newStreamCounter)
	require.Equal(t, firstStream+16, str.id)
	// and accept all of them
	for i := 1; i < 5; i++ {
		str, err := m.AcceptStream(ctx)
		require.NoError(t, err)
		require.Equal(t, firstStream+4*protocol.StreamID(i), str.id)
	}

	_, err = m.GetOrOpenStream(firstStream + 4*maxNumStreams - 4)
	require.NoError(t, err)
	_, err = m.GetOrOpenStream(firstStream + 4*maxNumStreams)
	require.ErrorIs(t, err, &qerr.TransportError{ErrorCode: qerr.StreamLimitError})
	require.ErrorContains(t, err, "peer tried to open stream")
	require.Equal(t, maxNumStreams, newStreamCounter)
}

func TestStreamsMapIncomingAcceptingStreams(t *testing.T) {
	m := newIncomingStreamsMap(
		protocol.StreamTypeUni,
		func(id protocol.StreamID) *mockStream { return &mockStream{id: id} },
		5,
		func(f wire.Frame) {},
		protocol.PerspectiveClient,
	)

	// AcceptStream should respect the context
	errChan := make(chan error, 1)
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

	_, err := m.GetOrOpenStream(protocol.FirstIncomingUniStreamClient)
	require.NoError(t, err)

	select {
	case err := <-errChan:
		require.NoError(t, err)
	case <-time.After(time.Second):
		t.Fatal("timeout")
	}
}

func TestStreamsMapIncomingDeletingStreams(t *testing.T) {
	t.Run("client", func(t *testing.T) {
		testStreamsMapIncomingDeletingStreams(t, protocol.PerspectiveClient, protocol.FirstIncomingUniStreamClient)
	})
	t.Run("server", func(t *testing.T) {
		testStreamsMapIncomingDeletingStreams(t, protocol.PerspectiveServer, protocol.FirstIncomingUniStreamServer)
	})
}

func testStreamsMapIncomingDeletingStreams(t *testing.T, perspective protocol.Perspective, firstStream protocol.StreamID) {
	var frameQueue []wire.Frame
	m := newIncomingStreamsMap(
		protocol.StreamTypeUni,
		func(id protocol.StreamID) *mockStream { return &mockStream{id: id} },
		5,
		func(f wire.Frame) { frameQueue = append(frameQueue, f) },
		perspective,
	)
	err := m.DeleteStream(firstStream + 1337*4)
	require.ErrorIs(t, err, &qerr.TransportError{ErrorCode: qerr.StreamStateError})
	require.ErrorContains(t, err, "tried to delete unknown incoming stream")

	s, err := m.GetOrOpenStream(firstStream + 4)
	require.NoError(t, err)
	require.NotNil(t, s)
	// delete the stream
	require.NoError(t, m.DeleteStream(firstStream+4))
	require.Empty(t, frameQueue)
	// it's not returned by GetOrOpenStream anymore
	s, err = m.GetOrOpenStream(firstStream + 4)
	require.NoError(t, err)
	require.Nil(t, s)

	// AcceptStream still returns this stream
	str, err := m.AcceptStream(context.Background())
	require.NoError(t, err)
	require.Equal(t, firstStream, str.id)
	require.Empty(t, frameQueue)

	str, err = m.AcceptStream(context.Background())
	require.NoError(t, err)
	require.Equal(t, firstStream+4, str.id)
	// now the stream is deleted and new stream credit is issued
	require.Len(t, frameQueue, 1)
	require.Equal(t, &wire.MaxStreamsFrame{Type: protocol.StreamTypeUni, MaxStreamNum: 6}, frameQueue[0])
	frameQueue = frameQueue[:0]

	require.NoError(t, m.DeleteStream(firstStream))
	require.Len(t, frameQueue, 1)
	require.Equal(t, &wire.MaxStreamsFrame{Type: protocol.StreamTypeUni, MaxStreamNum: 7}, frameQueue[0])
}

// There's a maximum number that can be encoded in a MAX_STREAMS frame.
// Since the stream limit is configurable by the user, we can't rely on this number
// being high enough that it will never be reached in practice.
func TestStreamsMapIncomingDeletingStreamsWithHighLimits(t *testing.T) {
	t.Run("client", func(t *testing.T) {
		testStreamsMapIncomingDeletingStreamsWithHighLimits(t, protocol.PerspectiveClient, protocol.FirstIncomingUniStreamClient)
	})
	t.Run("server", func(t *testing.T) {
		testStreamsMapIncomingDeletingStreamsWithHighLimits(t, protocol.PerspectiveServer, protocol.FirstIncomingUniStreamServer)
	})
}

func testStreamsMapIncomingDeletingStreamsWithHighLimits(t *testing.T, pers protocol.Perspective, firstStream protocol.StreamID) {
	var frameQueue []wire.Frame
	m := newIncomingStreamsMap(
		protocol.StreamTypeUni,
		func(id protocol.StreamID) *mockStream { return &mockStream{id: id} },
		uint64(protocol.MaxStreamCount-2),
		func(f wire.Frame) { frameQueue = append(frameQueue, f) },
		pers,
	)

	// open a bunch of streams
	_, err := m.GetOrOpenStream(firstStream + 16)
	require.NoError(t, err)
	// accept all streams
	for range 5 {
		_, err := m.AcceptStream(context.Background())
		require.NoError(t, err)
	}
	require.Empty(t, frameQueue)
	require.NoError(t, m.DeleteStream(firstStream+12))
	require.Len(t, frameQueue, 1)
	require.Equal(t,
		&wire.MaxStreamsFrame{Type: protocol.StreamTypeUni, MaxStreamNum: protocol.MaxStreamCount - 1},
		frameQueue[0],
	)
	require.NoError(t, m.DeleteStream(firstStream+8))
	require.Len(t, frameQueue, 2)
	require.Equal(t,
		&wire.MaxStreamsFrame{Type: protocol.StreamTypeUni, MaxStreamNum: protocol.MaxStreamCount},
		frameQueue[1],
	)
	// at this point, we can't increase the stream limit any further, so no more MAX_STREAMS frames will be sent
	require.NoError(t, m.DeleteStream(firstStream+4))
	require.NoError(t, m.DeleteStream(firstStream))
	require.Len(t, frameQueue, 2)
}

func TestStreamsMapIncomingClosing(t *testing.T) {
	m := newIncomingStreamsMap(
		protocol.StreamTypeUni,
		func(id protocol.StreamID) *mockStream { return &mockStream{id: id} },
		5,
		func(f wire.Frame) {},
		protocol.PerspectiveServer,
	)

	var streams []*mockStream
	_, err := m.GetOrOpenStream(protocol.FirstIncomingUniStreamServer + 8)
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

	m.CloseWithError(assert.AnError)

	// accepted streams should be closed
	for _, str := range streams {
		require.True(t, str.closed)
		require.ErrorIs(t, str.closeErr, assert.AnError)
	}
	// AcceptStream should return the error
	select {
	case err := <-errChan:
		require.ErrorIs(t, err, assert.AnError)
	case <-time.After(time.Second):
		t.Fatal("timeout")
	}
}

func TestStreamsMapIncomingRandomized(t *testing.T) {
	const num = 1000

	streamType := []protocol.StreamType{protocol.StreamTypeUni, protocol.StreamTypeBidi}[rand.IntN(2)]
	firstStream := protocol.FirstIncomingUniStreamServer
	if streamType == protocol.StreamTypeBidi {
		firstStream = protocol.FirstIncomingBidiStreamServer
	}

	m := newIncomingStreamsMap(
		streamType,
		func(id protocol.StreamID) *mockStream { return &mockStream{id: id} },
		num,
		func(f wire.Frame) {},
		protocol.PerspectiveServer,
	)

	ids := make([]protocol.StreamID, num)
	for i := range num {
		ids[i] = firstStream + 4*protocol.StreamID(i)
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
			if _, err := m.GetOrOpenStream(ids[i]); err != nil {
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
