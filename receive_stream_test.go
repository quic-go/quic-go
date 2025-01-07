package quic

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/quic-go/quic-go/internal/mocks"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/wire"

	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

type readerWithTimeout struct {
	io.Reader
	Timeout time.Duration
}

func (r *readerWithTimeout) Read(p []byte) (n int, err error) {
	done := make(chan struct{})
	go func() {
		defer close(done)
		n, err = r.Reader.Read(p)
	}()

	select {
	case <-done:
		return n, err
	case <-time.After(r.Timeout):
		return 0, fmt.Errorf("read timeout after %s", r.Timeout)
	}
}

func TestReceiveStreamReadData(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	mockFC := mocks.NewMockStreamFlowController(mockCtrl)
	str := newReceiveStream(42, nil, mockFC)

	// read an entire frame
	now := time.Now()
	mockFC.EXPECT().UpdateHighestReceived(protocol.ByteCount(4), false, now)
	mockFC.EXPECT().AddBytesRead(protocol.ByteCount(4))
	require.NoError(t, str.handleStreamFrame(&wire.StreamFrame{Data: []byte{0xde, 0xad, 0xbe, 0xef}}, now))
	b := make([]byte, 4)
	n, err := (&readerWithTimeout{Reader: str, Timeout: time.Second}).Read(b)
	require.NoError(t, err)
	require.Equal(t, 4, n)
	require.Equal(t, []byte{0xde, 0xad, 0xbe, 0xef}, b)

	// split a frame across multiple reads
	mockFC.EXPECT().UpdateHighestReceived(protocol.ByteCount(8), false, now)
	mockFC.EXPECT().AddBytesRead(protocol.ByteCount(2)).Times(2)
	require.NoError(t, str.handleStreamFrame(&wire.StreamFrame{Offset: 4, Data: []byte{0xca, 0xfe, 0xba, 0xbe}}, now))
	b = make([]byte, 2)
	n, err = (&readerWithTimeout{Reader: str, Timeout: time.Second}).Read(b)
	require.NoError(t, err)
	require.Equal(t, 2, n)
	require.Equal(t, []byte{0xca, 0xfe}, b)
	n, err = (&readerWithTimeout{Reader: str, Timeout: time.Second}).Read(b)
	require.NoError(t, err)
	require.Equal(t, 2, n)
	require.Equal(t, []byte{0xba, 0xbe}, b)

	// combine two frames
	gomock.InOrder(
		mockFC.EXPECT().UpdateHighestReceived(protocol.ByteCount(11), false, now),
		mockFC.EXPECT().UpdateHighestReceived(protocol.ByteCount(14), false, now),
		mockFC.EXPECT().AddBytesRead(protocol.ByteCount(3)).Times(2),
	)
	require.NoError(t, str.handleStreamFrame(&wire.StreamFrame{Offset: 8, Data: []byte{'f', 'o', 'o'}}, now))
	require.NoError(t, str.handleStreamFrame(&wire.StreamFrame{Offset: 11, Data: []byte{'b', 'a', 'r'}}, now))
	b = make([]byte, 6)
	n, err = (&readerWithTimeout{Reader: str, Timeout: time.Second}).Read(b)
	require.NoError(t, err)
	require.Equal(t, 6, n)
	require.Equal(t, []byte{'f', 'o', 'o', 'b', 'a', 'r'}, b)

	// reordered frames
	gomock.InOrder(
		mockFC.EXPECT().UpdateHighestReceived(protocol.ByteCount(20), false, now),
		mockFC.EXPECT().UpdateHighestReceived(protocol.ByteCount(17), false, now),
		mockFC.EXPECT().AddBytesRead(protocol.ByteCount(3)).Times(2),
	)
	require.NoError(t, str.handleStreamFrame(&wire.StreamFrame{Offset: 17, Data: []byte{'b', 'a', 'z'}}, now))
	require.NoError(t, str.handleStreamFrame(&wire.StreamFrame{Offset: 14, Data: []byte{'f', 'o', 'o'}}, now))
	b = make([]byte, 6)
	n, err = (&readerWithTimeout{Reader: str, Timeout: time.Second}).Read(b)
	require.NoError(t, err)
	require.Equal(t, 6, n)
	require.Equal(t, []byte{'f', 'o', 'o', 'b', 'a', 'z'}, b)
}

func TestReceiveStreamBlockRead(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	mockFC := mocks.NewMockStreamFlowController(mockCtrl)
	mockSender := NewMockStreamSender(mockCtrl)
	str := newReceiveStream(42, mockSender, mockFC)

	mockFC.EXPECT().UpdateHighestReceived(protocol.ByteCount(2), false, gomock.Any())
	mockFC.EXPECT().AddBytesRead(protocol.ByteCount(2))
	errChan := make(chan error, 1)
	go func() {
		frame := wire.StreamFrame{Data: []byte{0xDE, 0xAD}}
		time.Sleep(scaleDuration(5 * time.Millisecond))
		errChan <- str.handleStreamFrame(&frame, time.Now())
	}()

	n, err := (&readerWithTimeout{Reader: str, Timeout: time.Second}).Read(make([]byte, 2))
	require.NoError(t, err)
	require.Equal(t, 2, n)
	require.NoError(t, <-errChan)
}

func TestReceiveStreamReadOverlappingData(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	mockFC := mocks.NewMockStreamFlowController(mockCtrl)
	str := newReceiveStream(42, nil, mockFC)

	// receive the same frame multiple times
	now := time.Now()
	mockFC.EXPECT().UpdateHighestReceived(protocol.ByteCount(4), false, now).Times(3)
	mockFC.EXPECT().AddBytesRead(protocol.ByteCount(4))
	for i := 0; i < 3; i++ {
		require.NoError(t, str.handleStreamFrame(&wire.StreamFrame{Data: []byte{0xde, 0xad, 0xbe, 0xef}}, now))
	}
	b := make([]byte, 4)
	n, err := (&readerWithTimeout{Reader: str, Timeout: time.Second}).Read(b)
	require.NoError(t, err)
	require.Equal(t, 4, n)
	require.Equal(t, []byte{0xde, 0xad, 0xbe, 0xef}, b)

	// receive overlapping data
	gomock.InOrder(
		mockFC.EXPECT().UpdateHighestReceived(protocol.ByteCount(8), false, now),
		mockFC.EXPECT().UpdateHighestReceived(protocol.ByteCount(10), false, now),
		mockFC.EXPECT().AddBytesRead(protocol.ByteCount(4)),
		mockFC.EXPECT().AddBytesRead(protocol.ByteCount(2)),
	)
	require.NoError(t, str.handleStreamFrame(&wire.StreamFrame{Offset: 4, Data: []byte{'f', 'o', 'o', 'b'}}, now))
	require.NoError(t, str.handleStreamFrame(&wire.StreamFrame{Offset: 6, Data: []byte{'o', 'b', 'a', 'r'}}, now))
	b = make([]byte, 6)
	n, err = (&readerWithTimeout{Reader: str, Timeout: time.Second}).Read(b)
	require.NoError(t, err)
	require.Equal(t, 6, n)
	require.Equal(t, []byte{'f', 'o', 'o', 'b', 'a', 'r'}, b)
}

func TestReceiveStreamFlowControlUpdates(t *testing.T) {
	t.Run("stream", func(t *testing.T) {
		testReceiveStreamFlowControlUpdates(t, true, false)
	})

	t.Run("connection", func(t *testing.T) {
		testReceiveStreamFlowControlUpdates(t, false, true)
	})
}

func testReceiveStreamFlowControlUpdates(t *testing.T, hasStreamWindowUpdate, hasConnWindowUpdate bool) {
	const streamID protocol.StreamID = 42
	mockCtrl := gomock.NewController(t)
	mockFC := mocks.NewMockStreamFlowController(mockCtrl)
	mockSender := NewMockStreamSender(mockCtrl)
	str := newReceiveStream(streamID, mockSender, mockFC)

	now := time.Now()
	mockFC.EXPECT().UpdateHighestReceived(protocol.ByteCount(4), false, now)
	require.NoError(t, str.handleStreamFrame(&wire.StreamFrame{Data: []byte{0xde, 0xad, 0xbe, 0xef}}, now))

	mockFC.EXPECT().AddBytesRead(protocol.ByteCount(3)).Return(hasStreamWindowUpdate, hasConnWindowUpdate)
	if hasStreamWindowUpdate {
		mockSender.EXPECT().onHasStreamControlFrame(streamID, str)
	}
	if hasConnWindowUpdate {
		mockSender.EXPECT().onHasConnectionData()
	}
	n, err := (&readerWithTimeout{Reader: str, Timeout: time.Second}).Read(make([]byte, 3))
	require.NoError(t, err)
	require.Equal(t, 3, n)
	require.True(t, mockCtrl.Satisfied())

	if hasStreamWindowUpdate {
		now = now.Add(time.Second)
		mockFC.EXPECT().GetWindowUpdate(now).Return(protocol.ByteCount(1337))
		f, ok, hasMore := str.getControlFrame(now)
		require.True(t, ok)
		require.Equal(t, &wire.MaxStreamDataFrame{StreamID: streamID, MaximumStreamData: 1337}, f.Frame)
		require.False(t, hasMore)
	}
	if hasConnWindowUpdate {
		_, ok, hasMore := str.getControlFrame(now)
		require.False(t, ok)
		require.False(t, hasMore)
	}
}

func TestReceiveStreamDeadlineInThePast(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	mockFC := mocks.NewMockStreamFlowController(mockCtrl)
	str := newReceiveStream(42, nil, mockFC)

	// no data is read when the deadline is in the past
	mockFC.EXPECT().UpdateHighestReceived(protocol.ByteCount(6), false, gomock.Any()).AnyTimes()
	require.NoError(t, str.handleStreamFrame(&wire.StreamFrame{Data: []byte("foobar")}, time.Now()))
	require.NoError(t, str.SetReadDeadline(time.Now().Add(-time.Second)))
	b := make([]byte, 6)
	n, err := (&readerWithTimeout{Reader: str, Timeout: time.Second}).Read(b)
	require.Error(t, err)
	require.Zero(t, n)
	var nerr net.Error
	require.ErrorAs(t, err, &nerr)
	require.True(t, nerr.Timeout())

	// data is read when the deadline is in the future
	require.NoError(t, str.SetReadDeadline(time.Now().Add(time.Second)))
	mockFC.EXPECT().AddBytesRead(protocol.ByteCount(6))
	n, err = (&readerWithTimeout{Reader: str, Timeout: time.Second}).Read(b)
	require.NoError(t, err)
	require.Equal(t, 6, n)
}

func TestReceiveStreamDeadlineRemoval(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	mockFC := mocks.NewMockStreamFlowController(mockCtrl)
	str := newReceiveStream(42, nil, mockFC)

	deadline := scaleDuration(20 * time.Millisecond)
	require.NoError(t, str.SetReadDeadline(time.Now().Add(deadline)))
	errChan := make(chan error, 1)
	go func() {
		_, err := (&readerWithTimeout{Reader: str, Timeout: 5 * time.Second}).Read([]byte{0})
		errChan <- err
	}()
	select {
	case err := <-errChan:
		t.Fatalf("read should not have returned yet: %v", err)
	case <-time.After(deadline / 2):
	}

	// remove the deadline after a while (but before it expires)
	require.NoError(t, str.SetReadDeadline(time.Time{}))

	select {
	case err := <-errChan:
		t.Fatalf("read should not have returned yet: %v", err)
	case <-time.After(deadline):
	}

	// now set the deadline to the past to make Read return immediately
	require.NoError(t, str.SetReadDeadline(time.Now().Add(-time.Second)))
	select {
	case err := <-errChan:
		require.ErrorIs(t, err, os.ErrDeadlineExceeded)
	case <-time.After(time.Second):
		t.Fatal("timeout")
	}
}

func TestReceiveStreamDeadlineExtension(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	mockFC := mocks.NewMockStreamFlowController(mockCtrl)
	str := newReceiveStream(42, nil, mockFC)

	deadline := scaleDuration(20 * time.Millisecond)
	require.NoError(t, str.SetReadDeadline(time.Now().Add(deadline)))
	errChan := make(chan error, 1)
	go func() {
		_, err := (&readerWithTimeout{Reader: str, Timeout: 5 * time.Second}).Read([]byte{0})
		errChan <- err
	}()
	select {
	case err := <-errChan:
		t.Fatalf("read should not have returned yet: %v", err)
	case <-time.After(deadline / 2):
	}

	// extend the deadline
	require.NoError(t, str.SetReadDeadline(time.Now().Add(deadline)))
	select {
	case err := <-errChan:
		require.ErrorIs(t, err, os.ErrDeadlineExceeded)
	case <-time.After(deadline * 3 / 2):
		t.Fatal("timeout")
	}
}

func TestReceiveStreamEOFWithData(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	mockFC := mocks.NewMockStreamFlowController(mockCtrl)
	mockSender := NewMockStreamSender(mockCtrl)
	str := newReceiveStream(42, mockSender, mockFC)

	now := time.Now()
	mockFC.EXPECT().UpdateHighestReceived(protocol.ByteCount(4), true, now)
	mockFC.EXPECT().UpdateHighestReceived(protocol.ByteCount(2), false, now)
	require.NoError(t, str.handleStreamFrame(&wire.StreamFrame{Offset: 2, Data: []byte{0xbe, 0xef}, Fin: true}, now))
	require.NoError(t, str.handleStreamFrame(&wire.StreamFrame{Data: []byte{0xde, 0xad}}, now))
	mockFC.EXPECT().AddBytesRead(protocol.ByteCount(2)).Times(2)
	mockSender.EXPECT().onStreamCompleted(protocol.StreamID(42))

	strWithTimeout := &readerWithTimeout{Reader: str, Timeout: time.Second}
	b := make([]byte, 6)
	n, err := strWithTimeout.Read(b)
	require.ErrorIs(t, err, io.EOF)
	require.Equal(t, 4, n)
	require.Equal(t, []byte{0xde, 0xad, 0xbe, 0xef}, b[:n])
	n, err = strWithTimeout.Read(b)
	require.Zero(t, n)
	require.ErrorIs(t, err, io.EOF)
}

func TestReceiveStreamImmediateFINs(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	mockFC := mocks.NewMockStreamFlowController(mockCtrl)
	mockSender := NewMockStreamSender(mockCtrl)
	str := newReceiveStream(42, mockSender, mockFC)
	mockFC.EXPECT().UpdateHighestReceived(protocol.ByteCount(0), true, gomock.Any())
	mockFC.EXPECT().AddBytesRead(protocol.ByteCount(0))
	require.NoError(t, str.handleStreamFrame(&wire.StreamFrame{Fin: true}, time.Now()))
	mockSender.EXPECT().onStreamCompleted(protocol.StreamID(42))
	n, err := (&readerWithTimeout{Reader: str, Timeout: time.Second}).Read(make([]byte, 4))
	require.Zero(t, n)
	require.ErrorIs(t, err, io.EOF)
}

func TestReceiveStreamCloseForShutdown(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	mockFC := mocks.NewMockStreamFlowController(mockCtrl)
	mockSender := NewMockStreamSender(mockCtrl)
	str := newReceiveStream(42, mockSender, mockFC)
	strWithTimeout := &readerWithTimeout{Reader: str, Timeout: time.Second}

	// Test immediate return of reads
	errChan := make(chan error, 1)
	go func() {
		_, err := strWithTimeout.Read([]byte{0})
		errChan <- err
	}()

	select {
	case err := <-errChan:
		t.Fatalf("read returned before closeForShutdown: %v", err)
	case <-time.After(scaleDuration(5 * time.Millisecond)): // short wait to ensure read is blocked
	}

	testErr := errors.New("test error")
	str.closeForShutdown(testErr)
	select {
	case err := <-errChan:
		require.ErrorIs(t, err, testErr)
	case <-time.After(time.Second):
		t.Fatal("read did not return after closeForShutdown")
	}

	// following calls to Read should return the error
	n, err := strWithTimeout.Read([]byte{0})
	require.Zero(t, n)
	require.ErrorIs(t, err, testErr)

	// receiving a RESET_STREAM frame after closeForShutdown does nothing
	require.NoError(t, str.handleResetStreamFrame(&wire.ResetStreamFrame{StreamID: 42, ErrorCode: 1234, FinalSize: 42}, time.Now()))
	n, err = strWithTimeout.Read([]byte{0})
	require.Zero(t, n)
	require.ErrorIs(t, err, testErr)

	// calling CancelRead after closeForShutdown does nothing
	str.CancelRead(1234)
	n, err = strWithTimeout.Read([]byte{0})
	require.Zero(t, n)
	require.ErrorIs(t, err, testErr)
}

func TestReceiveStreamCancellation(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	mockFC := mocks.NewMockStreamFlowController(mockCtrl)
	mockSender := NewMockStreamSender(mockCtrl)
	str := newReceiveStream(42, mockSender, mockFC)
	strWithTimeout := &readerWithTimeout{Reader: str, Timeout: time.Second}

	mockSender.EXPECT().onHasStreamControlFrame(str.StreamID(), gomock.Any())
	errChan := make(chan error, 1)
	go func() {
		_, err := strWithTimeout.Read([]byte{0})
		errChan <- err
	}()

	select {
	case err := <-errChan:
		t.Fatalf("read returned before CancelRead: %v", err)
	case <-time.After(scaleDuration(5 * time.Millisecond)):
	}

	str.CancelRead(1234)
	// this queues a STOP_SENDING frame
	f, ok, hasMore := str.getControlFrame(time.Now())
	require.True(t, ok)
	require.Equal(t, &wire.StopSendingFrame{StreamID: 42, ErrorCode: 1234}, f.Frame)
	require.False(t, hasMore)
	require.True(t, mockCtrl.Satisfied())

	select {
	case err := <-errChan:
		var streamErr *StreamError
		require.ErrorAs(t, err, &streamErr)
		require.Equal(t, StreamError{StreamID: 42, ErrorCode: 1234, Remote: false}, *streamErr)
	case <-time.After(time.Second):
		t.Fatal("Read was not unblocked")
	}

	// further Read calls return the error
	n, err := strWithTimeout.Read([]byte{0})
	require.Zero(t, n)
	require.ErrorIs(t, err, &StreamError{StreamID: 42, ErrorCode: 1234, Remote: false})

	// calling CancelRead again does nothing
	// especially:
	// 1. no more calls to onHasStreamControlFrame
	// 2. no changes of the error code returned by Read
	str.CancelRead(1234)
	str.CancelRead(4321)
	n, err = strWithTimeout.Read([]byte{0})
	require.Zero(t, n)
	// error code unchanged
	require.ErrorIs(t, err, &StreamError{StreamID: 42, ErrorCode: 1234, Remote: false})
	require.True(t, mockCtrl.Satisfied())

	// receiving the FIN bit has no effect
	mockFC.EXPECT().Abandon()
	mockFC.EXPECT().UpdateHighestReceived(protocol.ByteCount(6), true, gomock.Any()).Times(2)
	mockSender.EXPECT().onStreamCompleted(protocol.StreamID(42))
	// receive two of them, to make sure onStreamCompleted is not called twice
	require.NoError(t, str.handleStreamFrame(&wire.StreamFrame{Data: []byte("foobar"), Fin: true}, time.Now()))
	require.NoError(t, str.handleStreamFrame(&wire.StreamFrame{Data: []byte("foobar"), Fin: true}, time.Now()))
	require.True(t, mockCtrl.Satisfied())

	// receiving a RESET_STREAM frame after CancelRead has no effect
	mockFC.EXPECT().Abandon()
	mockFC.EXPECT().UpdateHighestReceived(protocol.ByteCount(42), true, gomock.Any())
	require.NoError(t, str.handleResetStreamFrame(&wire.ResetStreamFrame{StreamID: 42, ErrorCode: 4321, FinalSize: 42}, time.Now()))
	n, err = strWithTimeout.Read([]byte{0})
	require.Zero(t, n)
	require.ErrorIs(t, err, &StreamError{StreamID: 42, ErrorCode: 1234, Remote: false})
}

func TestReceiveStreamCancelReadAfterFINReceived(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	mockFC := mocks.NewMockStreamFlowController(mockCtrl)
	mockSender := NewMockStreamSender(mockCtrl)
	str := newReceiveStream(42, mockSender, mockFC)

	mockFC.EXPECT().UpdateHighestReceived(protocol.ByteCount(6), true, gomock.Any())
	mockSender.EXPECT().onStreamCompleted(protocol.StreamID(42))
	require.NoError(t, str.handleStreamFrame(&wire.StreamFrame{Data: []byte("foobar"), Fin: true}, time.Now()))

	// if the FIN was received, but not read yet, a STOP_SENDING frame is queued
	mockSender.EXPECT().onHasStreamControlFrame(str.StreamID(), str)
	mockFC.EXPECT().Abandon()
	str.CancelRead(1337)
	f, ok, hasMore := str.getControlFrame(time.Now())
	require.True(t, ok)
	require.Equal(t, &wire.StopSendingFrame{StreamID: 42, ErrorCode: 1337}, f.Frame)
	require.False(t, hasMore)

	// Read returns the error
	n, err := str.Read([]byte{0})
	require.Zero(t, n)
	require.ErrorIs(t, err, &StreamError{StreamID: 42, ErrorCode: 1337, Remote: false})
}

func TestReceiveStreamCancelReadAfterFINRead(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	mockFC := mocks.NewMockStreamFlowController(mockCtrl)
	mockSender := NewMockStreamSender(mockCtrl)
	str := newReceiveStream(42, mockSender, mockFC)

	mockFC.EXPECT().UpdateHighestReceived(protocol.ByteCount(6), true, gomock.Any())
	mockFC.EXPECT().AddBytesRead(protocol.ByteCount(6))
	mockSender.EXPECT().onStreamCompleted(protocol.StreamID(42))
	require.NoError(t, str.handleStreamFrame(&wire.StreamFrame{Data: []byte("foobar"), Fin: true}, time.Now()))
	n, err := str.Read(make([]byte, 10))
	require.ErrorIs(t, err, io.EOF)
	require.Equal(t, 6, n)

	// if the EOF was already read, no STOP_SENDING frame is queued
	str.CancelRead(1234)
	_, ok, hasMore := str.getControlFrame(time.Now())
	require.False(t, ok)
	require.False(t, hasMore)

	// Read returns the error
	n, err = str.Read([]byte{0})
	require.Zero(t, n)
	require.ErrorIs(t, err, io.EOF)
}

func TestReceiveStreamReset(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	mockFC := mocks.NewMockStreamFlowController(mockCtrl)
	mockSender := NewMockStreamSender(mockCtrl)
	str := newReceiveStream(42, mockSender, mockFC)
	strWithTimeout := &readerWithTimeout{Reader: str, Timeout: time.Second}

	errChan := make(chan error, 1)
	go func() {
		_, err := strWithTimeout.Read([]byte{0})
		errChan <- err
	}()

	select {
	case err := <-errChan:
		t.Fatalf("read returned before reset: %v", err)
	case <-time.After(scaleDuration(5 * time.Millisecond)):
	}

	mockSender.EXPECT().onStreamCompleted(protocol.StreamID(42))
	gomock.InOrder(
		mockFC.EXPECT().UpdateHighestReceived(protocol.ByteCount(42), true, gomock.Any()),
		mockFC.EXPECT().Abandon(),
	)
	require.NoError(t, str.handleResetStreamFrame(
		&wire.ResetStreamFrame{StreamID: 42, ErrorCode: 1234, FinalSize: 42},
		time.Now(),
	))

	select {
	case err := <-errChan:
		require.ErrorIs(t, err, &StreamError{StreamID: 42, ErrorCode: 1234, Remote: true})
	case <-time.After(time.Second):
		t.Fatal("Read was not unblocked")
	}

	// Test that further calls to Read return the error
	_, err := strWithTimeout.Read([]byte{0})
	require.Equal(t, &StreamError{StreamID: 42, ErrorCode: 1234, Remote: true}, err)

	// further RESET_STREAM frames have no effect
	mockFC.EXPECT().UpdateHighestReceived(protocol.ByteCount(42), true, gomock.Any())
	require.NoError(t, str.handleResetStreamFrame(
		&wire.ResetStreamFrame{StreamID: 42, ErrorCode: 4321, FinalSize: 42},
		time.Now(),
	))
	n, err := str.Read([]byte{0})
	require.Zero(t, n)
	// error code unchanged
	require.ErrorIs(t, err, &StreamError{StreamID: 42, ErrorCode: 1234, Remote: true})

	// CancelRead after a RESET_STREAM frame has no effect
	str.CancelRead(100)
	n, err = str.Read([]byte{0})
	require.Zero(t, n)
	// error code and remote flag unchanged
	require.ErrorIs(t, err, &StreamError{StreamID: 42, ErrorCode: 1234, Remote: true})
}

func TestReceiveStreamResetAfterFINRead(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	mockFC := mocks.NewMockStreamFlowController(mockCtrl)
	mockSender := NewMockStreamSender(mockCtrl)
	str := newReceiveStream(42, mockSender, mockFC)
	mockFC.EXPECT().UpdateHighestReceived(protocol.ByteCount(6), true, gomock.Any())
	mockSender.EXPECT().onStreamCompleted(protocol.StreamID(42))
	require.NoError(t, str.handleStreamFrame(
		&wire.StreamFrame{StreamID: 42, Data: []byte("foobar"), Fin: true},
		time.Now(),
	))
	mockFC.EXPECT().AddBytesRead(protocol.ByteCount(6))
	n, err := str.Read(make([]byte, 6))
	require.Equal(t, 6, n)
	require.ErrorIs(t, err, io.EOF)
	// make sure that onStreamCompleted was called due to the EOF
	require.True(t, mockCtrl.Satisfied())

	// Now receive a RESET_STREAM frame.
	// We don't expect any more calls to onStreamCompleted.
	mockFC.EXPECT().UpdateHighestReceived(protocol.ByteCount(6), true, gomock.Any())
	mockFC.EXPECT().Abandon()
	require.NoError(t, str.handleResetStreamFrame(
		&wire.ResetStreamFrame{StreamID: 42, ErrorCode: 1234, FinalSize: 6},
		time.Now(),
	))
	// now read the error
	n, err = str.Read([]byte{0})
	require.Error(t, err)
	require.Zero(t, n)
}

// Calling Read concurrently doesn't make any sense (and is forbidden),
// but we still want to make sure that we don't complete the stream more than once
// if the user misuses our API.
// This would lead to an INTERNAL_ERROR ("tried to delete unknown outgoing stream"),
// which can be hard to debug.
// Note that even without the protection built into the receiveStream, this test
// is very timing-dependent, and would need to run a few hundred times to trigger the failure.
func TestReceiveStreamConcurrentReads(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	mockFC := mocks.NewMockStreamFlowController(mockCtrl)
	mockSender := NewMockStreamSender(mockCtrl)
	str := newReceiveStream(42, mockSender, mockFC)

	mockFC.EXPECT().UpdateHighestReceived(protocol.ByteCount(6), gomock.Any(), gomock.Any()).AnyTimes()
	var bytesRead protocol.ByteCount
	mockFC.EXPECT().AddBytesRead(gomock.Any()).Do(func(n protocol.ByteCount) (bool, bool) {
		bytesRead += n
		return false, false
	}).AnyTimes()

	var numCompleted atomic.Int32
	mockSender.EXPECT().onStreamCompleted(protocol.StreamID(42)).Do(func(protocol.StreamID) {
		numCompleted.Add(1)
	}).AnyTimes()

	const num = 3
	errChan := make(chan error, num)
	for i := 0; i < num; i++ {
		go func() {
			_, err := str.Read(make([]byte, 8))
			errChan <- err
		}()
	}
	require.NoError(t, str.handleStreamFrame(&wire.StreamFrame{Data: []byte("foobar"), Fin: true}, time.Now()))
	for i := 0; i < num; i++ {
		select {
		case err := <-errChan:
			require.ErrorIs(t, err, io.EOF)
		case <-time.After(time.Second):
			t.Fatal("timeout")
		}
	}
	require.Equal(t, protocol.ByteCount(6), bytesRead)
	require.Equal(t, int32(1), numCompleted.Load())
}
