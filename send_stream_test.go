package quic

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	mrand "math/rand/v2"
	"net"
	"os"
	"testing"
	"time"

	"github.com/quic-go/quic-go/internal/mocks"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/wire"

	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

type writerWithTimeout struct {
	io.Writer
	Timeout time.Duration
}

func (w *writerWithTimeout) Write(p []byte) (n int, err error) {
	done := make(chan struct{})
	go func() {
		defer close(done)
		n, err = w.Writer.Write(p)
	}()

	select {
	case <-done:
		return n, err
	case <-time.After(w.Timeout):
		return 0, fmt.Errorf("write timeout after %s", w.Timeout)
	}
}

func expectedFrameHeaderLen(strID protocol.StreamID, offset protocol.ByteCount) protocol.ByteCount {
	return (&wire.StreamFrame{StreamID: strID, Offset: offset, DataLenPresent: true}).Length(protocol.Version1)
}

func TestSendStreamSetup(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	mockFC := mocks.NewMockStreamFlowController(mockCtrl)
	ctx := context.WithValue(context.Background(), "foo", "bar")
	str := newSendStream(ctx, 1337, nil, mockFC)
	require.NotNil(t, str.Context())
	require.Equal(t, "bar", str.Context().Value("foo"))
	require.Equal(t, protocol.StreamID(1337), str.StreamID())
}

func TestSendStreamWriteData(t *testing.T) {
	const streamID protocol.StreamID = 42
	mockCtrl := gomock.NewController(t)
	mockFC := mocks.NewMockStreamFlowController(mockCtrl)
	mockSender := NewMockStreamSender(mockCtrl)
	str := newSendStream(context.Background(), streamID, mockSender, mockFC)
	strWithTimeout := &writerWithTimeout{Writer: str, Timeout: time.Second}

	mockSender.EXPECT().onHasStreamData(streamID, str)
	n, err := strWithTimeout.Write([]byte("foobar"))
	require.NoError(t, err)
	require.Equal(t, 6, n)

	mockFC.EXPECT().SendWindowSize().Return(protocol.MaxByteCount)
	mockFC.EXPECT().AddBytesSent(protocol.ByteCount(6))
	frame, _, hasMore := str.popStreamFrame(protocol.MaxByteCount, protocol.Version1)
	require.False(t, hasMore)
	require.EqualExportedValues(t,
		&wire.StreamFrame{StreamID: streamID, Data: []byte("foobar"), DataLenPresent: true},
		frame.Frame,
	)
	require.True(t, mockCtrl.Satisfied())

	// nothing more to send at this point
	_, _, hasMore = str.popStreamFrame(protocol.MaxByteCount, protocol.Version1)
	require.False(t, hasMore)
	require.True(t, mockCtrl.Satisfied())

	// nil writes don't do anything
	n, err = strWithTimeout.Write(nil)
	require.NoError(t, err)
	require.Zero(t, n)
	require.True(t, mockCtrl.Satisfied())

	// empty slices writes don't do anything
	n, err = strWithTimeout.Write([]byte{})
	require.NoError(t, err)
	require.Zero(t, n)
	require.True(t, mockCtrl.Satisfied())

	// multiple writes are bundled into a single frame
	mockSender.EXPECT().onHasStreamData(streamID, str).Times(2)
	n, err = strWithTimeout.Write([]byte{0xde, 0xad})
	require.NoError(t, err)
	require.Equal(t, 2, n)
	n, err = strWithTimeout.Write([]byte{0xbe, 0xef})
	require.NoError(t, err)
	require.Equal(t, 2, n)

	mockFC.EXPECT().SendWindowSize().Return(protocol.MaxByteCount)
	mockFC.EXPECT().AddBytesSent(protocol.ByteCount(4))
	frame, _, hasMore = str.popStreamFrame(protocol.MaxByteCount, protocol.Version1)
	require.False(t, hasMore)
	require.EqualExportedValues(t,
		&wire.StreamFrame{StreamID: 42, Offset: 6, Data: []byte{0xde, 0xad, 0xbe, 0xef}, DataLenPresent: true},
		frame.Frame,
	)

	// a single write is split up into smaller frames
	mockSender.EXPECT().onHasStreamData(streamID, str)
	n, err = strWithTimeout.Write([]byte("foobaz"))
	require.NoError(t, err)
	require.Equal(t, 6, n)
	mockFC.EXPECT().SendWindowSize().Return(protocol.MaxByteCount).Times(3)
	mockFC.EXPECT().AddBytesSent(protocol.ByteCount(3)).Times(2)
	frame, _, hasMore = str.popStreamFrame(expectedFrameHeaderLen(streamID, 10), protocol.Version1)
	require.Nil(t, frame.Frame)
	require.True(t, hasMore)
	frame, _, hasMore = str.popStreamFrame(expectedFrameHeaderLen(streamID, 10)+3, protocol.Version1)
	require.True(t, hasMore)
	require.EqualExportedValues(t,
		&wire.StreamFrame{StreamID: streamID, Offset: 10, Data: []byte("foo"), DataLenPresent: true},
		frame.Frame,
	)
	frame, _, hasMore = str.popStreamFrame(expectedFrameHeaderLen(streamID, 13)+3, protocol.Version1)
	require.False(t, hasMore)
	require.EqualExportedValues(t,
		&wire.StreamFrame{StreamID: streamID, Offset: 13, Data: []byte("baz"), DataLenPresent: true},
		frame.Frame,
	)
}

func TestSendStreamLargeWrites(t *testing.T) {
	const streamID protocol.StreamID = 1337
	mockCtrl := gomock.NewController(t)
	mockFC := mocks.NewMockStreamFlowController(mockCtrl)
	mockSender := NewMockStreamSender(mockCtrl)
	str := newSendStream(context.Background(), streamID, mockSender, mockFC)

	mockSender.EXPECT().onHasStreamData(streamID, str)
	data := make([]byte, 5000)
	rand.Read(data)
	errChan := make(chan error, 1)
	go func() {
		_, err := (&writerWithTimeout{Writer: str, Timeout: time.Second}).Write(data)
		str.Close()
		errChan <- err
	}()
	select {
	case err := <-errChan:
		require.NoError(t, err)
	case <-time.After(scaleDuration(5 * time.Millisecond)): // short wait to ensure write is blocked
	}

	mockFC.EXPECT().SendWindowSize().Return(protocol.MaxPacketBufferSize).AnyTimes()
	mockFC.EXPECT().AddBytesSent(gomock.Any()).AnyTimes()
	var offset protocol.ByteCount
	const size = 40
	for offset+size < protocol.ByteCount(len(data))-protocol.MaxPacketBufferSize {
		frame, _, hasMore := str.popStreamFrame(size+expectedFrameHeaderLen(streamID, offset), protocol.Version1)
		require.NotNil(t, frame.Frame)
		require.True(t, hasMore)
		require.Equal(t, offset, frame.Frame.Offset)
		require.Equal(t, data[offset:offset+size], frame.Frame.Data)
		offset += size
		require.True(t, mockCtrl.Satisfied())
	}
	// Write should still be blocked, since there's more than protocol.MaxPacketBufferSize left to send
	select {
	case err := <-errChan:
		require.NoError(t, err)
	case <-time.After(scaleDuration(5 * time.Millisecond)): // short wait to ensure write is blocked
	}

	mockSender.EXPECT().onHasStreamData(streamID, str) // from the Close call
	frame, _, hasMore := str.popStreamFrame(size+expectedFrameHeaderLen(streamID, offset), protocol.Version1)
	require.NotNil(t, frame.Frame)
	require.True(t, hasMore)
	require.Equal(t, data[offset:offset+size], frame.Frame.Data)
	require.Equal(t, offset, frame.Frame.Offset)
	offset += size
	select {
	case err := <-errChan:
		require.NoError(t, err)
	case <-time.After(time.Second):
		t.Fatal("timeout")
	}

	frame, _, hasMore = str.popStreamFrame(protocol.MaxByteCount, protocol.Version1)
	require.NotNil(t, frame.Frame)
	require.False(t, hasMore)
	require.Equal(t, data[offset:], frame.Frame.Data)
	require.True(t, frame.Frame.Fin)
}

func TestSendStreamLargeWriteBlocking(t *testing.T) {
	const streamID protocol.StreamID = 1337
	mockCtrl := gomock.NewController(t)
	mockFC := mocks.NewMockStreamFlowController(mockCtrl)
	mockSender := NewMockStreamSender(mockCtrl)
	str := newSendStream(context.Background(), streamID, mockSender, mockFC)

	mockSender.EXPECT().onHasStreamData(streamID, str).Times(2)
	_, err := (&writerWithTimeout{Writer: str, Timeout: time.Second}).Write([]byte("foobar"))
	require.NoError(t, err)
	errChan := make(chan error, 1)
	go func() {
		_, err := (&writerWithTimeout{Writer: str, Timeout: time.Second}).Write(make([]byte, protocol.MaxPacketBufferSize))
		errChan <- err
	}()

	select {
	case err := <-errChan:
		t.Fatalf("write should not have returned yet: %v", err)
	case <-time.After(scaleDuration(5 * time.Millisecond)):
	}

	mockFC.EXPECT().SendWindowSize().Return(protocol.MaxByteCount).Times(2)
	mockFC.EXPECT().AddBytesSent(protocol.ByteCount(3))
	frame, _, hasMoreData := str.popStreamFrame(expectedFrameHeaderLen(streamID, 0)+3, protocol.Version1)
	require.NotNil(t, frame.Frame)
	require.True(t, hasMoreData)
	require.Equal(t, []byte("foo"), frame.Frame.Data)

	select {
	case err := <-errChan:
		t.Fatalf("write should not have returned yet: %v", err)
	case <-time.After(scaleDuration(5 * time.Millisecond)):
	}

	mockFC.EXPECT().AddBytesSent(protocol.ByteCount(3))
	frame, _, hasMoreData = str.popStreamFrame(expectedFrameHeaderLen(streamID, 3)+3, protocol.Version1)
	require.NotNil(t, frame.Frame)
	require.True(t, hasMoreData)
	require.Equal(t, []byte("bar"), frame.Frame.Data)

	select {
	case err := <-errChan:
		require.NoError(t, err)
	case <-time.After(time.Second):
		t.Fatal("timeout")
	}
}

func TestSendStreamCopyData(t *testing.T) {
	const streamID protocol.StreamID = 42
	mockCtrl := gomock.NewController(t)
	mockFC := mocks.NewMockStreamFlowController(mockCtrl)
	mockSender := NewMockStreamSender(mockCtrl)
	str := newSendStream(context.Background(), streamID, mockSender, mockFC)
	strWithTimeout := &writerWithTimeout{Writer: str, Timeout: time.Second}

	// for small writes
	data := []byte("foobar")
	mockSender.EXPECT().onHasStreamData(streamID, str)
	_, err := strWithTimeout.Write(data)
	require.NoError(t, err)
	mockFC.EXPECT().SendWindowSize().Return(protocol.MaxByteCount)
	mockFC.EXPECT().AddBytesSent(gomock.Any())
	frame, _, _ := str.popStreamFrame(protocol.MaxPacketBufferSize, protocol.Version1)
	data[1] = 'e' // modify the data after it has been written
	require.EqualExportedValues(t,
		&wire.StreamFrame{StreamID: streamID, Data: []byte("foobar"), DataLenPresent: true},
		frame.Frame,
	)
}

func TestSendStreamDeadlineInThePast(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	mockFC := mocks.NewMockStreamFlowController(mockCtrl)
	mockSender := NewMockStreamSender(mockCtrl)
	str := newSendStream(context.Background(), 42, mockSender, mockFC)

	// no data is written when the deadline is in the past
	require.NoError(t, str.SetWriteDeadline(time.Now().Add(-time.Second)))
	n, err := (&writerWithTimeout{Writer: str, Timeout: time.Second}).Write([]byte("foobar"))
	require.ErrorIs(t, err, os.ErrDeadlineExceeded)
	require.Zero(t, n)
	var nerr net.Error
	require.ErrorAs(t, err, &nerr)
	require.True(t, nerr.Timeout())

	// data is written when the deadline is in the future
	mockSender.EXPECT().onHasStreamData(gomock.Any(), str)
	require.NoError(t, str.SetWriteDeadline(time.Now().Add(time.Second)))
	n, err = (&writerWithTimeout{Writer: str, Timeout: time.Second}).Write([]byte("foobar"))
	require.NoError(t, err)
	require.Equal(t, 6, n)
}

func TestSendStreamDeadlineRemoval(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	mockFC := mocks.NewMockStreamFlowController(mockCtrl)
	mockSender := NewMockStreamSender(mockCtrl)
	str := newSendStream(context.Background(), 42, mockSender, mockFC)

	deadline := scaleDuration(20 * time.Millisecond)
	require.NoError(t, str.SetWriteDeadline(time.Now().Add(deadline)))
	mockSender.EXPECT().onHasStreamData(gomock.Any(), str).Times(2)

	// small writes are written immediately
	_, err := (&writerWithTimeout{Writer: str, Timeout: time.Second}).Write([]byte("foobar"))
	require.NoError(t, err)

	// large writes might block, and therefore subject to the deadline
	errChan := make(chan error, 1)
	go func() {
		_, err := (&writerWithTimeout{Writer: str, Timeout: 5 * time.Second}).Write(make([]byte, 2000))
		errChan <- err
	}()
	select {
	case err := <-errChan:
		t.Fatalf("write should not have returned yet: %v", err)
	case <-time.After(deadline / 2):
	}

	// remove the deadline after a while (but before it expires)
	require.NoError(t, str.SetWriteDeadline(time.Time{}))

	select {
	case err := <-errChan:
		t.Fatalf("write should not have returned yet: %v", err)
	case <-time.After(deadline):
	}

	// now set the deadline to the past to make Write return immediately
	require.NoError(t, str.SetWriteDeadline(time.Now().Add(-time.Second)))
	select {
	case err := <-errChan:
		require.ErrorIs(t, err, os.ErrDeadlineExceeded)
	case <-time.After(time.Second):
		t.Fatal("timeout")
	}

	mockFC.EXPECT().SendWindowSize().Return(protocol.MaxByteCount)
	mockFC.EXPECT().AddBytesSent(gomock.Any())
	frame, _, hasMoreData := str.popStreamFrame(protocol.MaxByteCount, protocol.Version1)
	require.NotNil(t, frame.Frame)
	require.False(t, hasMoreData)
	require.Equal(t, []byte("foobar"), frame.Frame.Data)
}

func TestSendStreamDeadlineExtension(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	mockFC := mocks.NewMockStreamFlowController(mockCtrl)
	mockSender := NewMockStreamSender(mockCtrl)
	str := newSendStream(context.Background(), 42, mockSender, mockFC)

	deadline := scaleDuration(20 * time.Millisecond)
	require.NoError(t, str.SetWriteDeadline(time.Now().Add(deadline)))

	mockSender.EXPECT().onHasStreamData(gomock.Any(), str)
	errChan := make(chan error, 1)
	go func() {
		_, err := (&writerWithTimeout{Writer: str, Timeout: 5 * time.Second}).Write(make([]byte, 2000))
		errChan <- err
	}()
	select {
	case err := <-errChan:
		t.Fatalf("write should not have returned yet: %v", err)
	case <-time.After(deadline / 2):
	}

	// extend the deadline
	require.NoError(t, str.SetWriteDeadline(time.Now().Add(deadline)))
	select {
	case err := <-errChan:
		require.ErrorIs(t, err, os.ErrDeadlineExceeded)
	case <-time.After(deadline * 3 / 2):
		t.Fatal("timeout")
	}

	frame, _, hasMoreData := str.popStreamFrame(protocol.MaxByteCount, protocol.Version1)
	require.Nil(t, frame.Frame)
	require.False(t, hasMoreData)
}

func TestSendStreamClose(t *testing.T) {
	const streamID protocol.StreamID = 1234
	mockCtrl := gomock.NewController(t)
	mockFC := mocks.NewMockStreamFlowController(mockCtrl)
	mockSender := NewMockStreamSender(mockCtrl)
	str := newSendStream(context.Background(), streamID, mockSender, mockFC)
	strWithTimeout := &writerWithTimeout{Writer: str, Timeout: time.Second}

	mockSender.EXPECT().onHasStreamData(streamID, str).Times(2)
	_, err := strWithTimeout.Write([]byte("foobar"))
	require.NoError(t, err)
	require.NoError(t, str.Close())

	select {
	case <-str.Context().Done():
	default:
		t.Fatal("stream context should have been canceled")
	}

	mockFC.EXPECT().SendWindowSize().Return(protocol.MaxByteCount).Times(2)
	mockFC.EXPECT().AddBytesSent(protocol.ByteCount(3)).Times(2)
	frame, _, hasMore := str.popStreamFrame(expectedFrameHeaderLen(streamID, 0)+3, protocol.Version1)
	require.NotNil(t, frame.Frame)
	require.True(t, hasMore)
	require.EqualExportedValues(t,
		&wire.StreamFrame{StreamID: streamID, Offset: 0, Data: []byte("foo"), DataLenPresent: true}, // no FIN yet
		frame.Frame,
	)
	frame, _, hasMore = str.popStreamFrame(protocol.MaxByteCount, protocol.Version1)
	require.False(t, hasMore)
	require.EqualExportedValues(t,
		&wire.StreamFrame{StreamID: streamID, Offset: 3, Fin: true, Data: []byte("bar"), DataLenPresent: true},
		frame.Frame,
	)
	require.True(t, mockCtrl.Satisfied())

	// further calls to Write return an error
	_, err = strWithTimeout.Write([]byte("foobar"))
	require.ErrorContains(t, err, "write on closed stream 1234")
	frame, _, hasMore = str.popStreamFrame(protocol.MaxByteCount, protocol.Version1)
	require.Nil(t, frame.Frame)
	require.False(t, hasMore)

	// further calls to Close don't do anything
	require.NoError(t, str.Close())
	frame, _, hasMore = str.popStreamFrame(protocol.MaxByteCount, protocol.Version1)
	require.Nil(t, frame.Frame)
	require.False(t, hasMore)
	require.True(t, mockCtrl.Satisfied())

	// shutting down has no effect
	str.closeForShutdown(errors.New("goodbye"))
	_, err = strWithTimeout.Write([]byte("foobar"))
	require.ErrorContains(t, err, "write on closed stream 1234")
}

func TestSendStreamImmediateClose(t *testing.T) {
	const streamID protocol.StreamID = 1337
	mockCtrl := gomock.NewController(t)
	mockFC := mocks.NewMockStreamFlowController(mockCtrl)
	mockSender := NewMockStreamSender(mockCtrl)
	str := newSendStream(context.Background(), streamID, mockSender, mockFC)
	mockSender.EXPECT().onHasStreamData(streamID, str)
	require.NoError(t, str.Close())
	frame, _, hasMore := str.popStreamFrame(expectedFrameHeaderLen(streamID, 13)+3, protocol.Version1)
	require.False(t, hasMore)
	require.EqualExportedValues(t,
		&wire.StreamFrame{StreamID: streamID, Fin: true, DataLenPresent: true},
		frame.Frame,
	)
}

func TestSendStreamFlowControlBlocked(t *testing.T) {
	const streamID protocol.StreamID = 42
	mockCtrl := gomock.NewController(t)
	mockFC := mocks.NewMockStreamFlowController(mockCtrl)
	mockSender := NewMockStreamSender(mockCtrl)
	str := newSendStream(context.Background(), streamID, mockSender, mockFC)

	mockSender.EXPECT().onHasStreamData(streamID, str)
	_, err := str.Write([]byte("foobar"))
	require.NoError(t, err)

	mockFC.EXPECT().SendWindowSize().Return(protocol.ByteCount(3))
	mockFC.EXPECT().AddBytesSent(protocol.ByteCount(3))
	mockFC.EXPECT().SendWindowSize().Return(protocol.ByteCount(0))
	mockFC.EXPECT().IsNewlyBlocked().Return(true)
	frame, blocked, hasMore := str.popStreamFrame(protocol.MaxByteCount, protocol.Version1)
	require.True(t, hasMore)
	require.EqualExportedValues(t,
		&wire.StreamFrame{StreamID: streamID, Data: []byte("foo"), DataLenPresent: true},
		frame.Frame,
	)
	require.Equal(t, &wire.StreamDataBlockedFrame{StreamID: streamID, MaximumStreamData: 3}, blocked)

	frame, blocked, hasMore = str.popStreamFrame(protocol.MaxByteCount, protocol.Version1)
	require.Nil(t, frame.Frame)
	require.Nil(t, blocked)
	require.True(t, hasMore)

	_, ok, hasMore := str.getControlFrame(time.Now())
	require.False(t, ok)
	require.False(t, hasMore)
}

func TestSendStreamCloseForShutdown(t *testing.T) {
	const streamID protocol.StreamID = 1337
	mockCtrl := gomock.NewController(t)
	mockFC := mocks.NewMockStreamFlowController(mockCtrl)
	mockSender := NewMockStreamSender(mockCtrl)
	str := newSendStream(context.Background(), streamID, mockSender, mockFC)
	strWithTimeout := &writerWithTimeout{Writer: str, Timeout: time.Second}

	mockSender.EXPECT().onHasStreamData(streamID, str)
	errChan := make(chan error, 1)
	go func() {
		_, err := strWithTimeout.Write(bytes.Repeat([]byte("foobar"), 1000))
		errChan <- err
	}()

	select {
	case err := <-errChan:
		t.Fatalf("write returned before closeForShutdown: %v", err)
	case <-time.After(scaleDuration(5 * time.Millisecond)): // short wait to ensure write is blocked
	}

	testErr := errors.New("test error")
	str.closeForShutdown(testErr)
	require.True(t, mockCtrl.Satisfied())

	select {
	case err := <-errChan:
		require.ErrorIs(t, err, testErr)
	case <-time.After(time.Second):
		t.Fatal("timeout")
	}

	// future calls to Write should return the error
	_, err := strWithTimeout.Write([]byte("foobar"))
	require.ErrorIs(t, err, testErr)

	// closing the stream doesn't do anything
	require.NoError(t, str.Close())

	// no STREAM frames popped
	frame, _, hasMore := str.popStreamFrame(protocol.MaxByteCount, protocol.Version1)
	require.Nil(t, frame.Frame)
	require.False(t, hasMore)

	// canceling the stream doesn't do anything
	str.CancelWrite(1234)
	_, err = strWithTimeout.Write([]byte("foobar"))
	require.ErrorIs(t, err, testErr) // error unchanged
}

func TestSendStreamUpdateSendWindow(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	mockFC := mocks.NewMockStreamFlowController(mockCtrl)
	mockSender := NewMockStreamSender(mockCtrl)
	str := newSendStream(context.Background(), 42, mockSender, mockFC)

	mockSender.EXPECT().onHasStreamData(gomock.Any(), str)
	_, err := str.Write([]byte("foobar"))
	require.NoError(t, err)
	require.True(t, mockCtrl.Satisfied())

	// no calls to onHasStreamData if the window size wasn't increased
	mockFC.EXPECT().UpdateSendWindow(protocol.ByteCount(41)).Return(false)
	str.updateSendWindow(41)
}

func TestSendStreamCancellation(t *testing.T) {
	const streamID protocol.StreamID = 42
	mockCtrl := gomock.NewController(t)
	mockFC := mocks.NewMockStreamFlowController(mockCtrl)
	mockSender := NewMockStreamSender(mockCtrl)
	str := newSendStream(context.Background(), streamID, mockSender, mockFC)
	strWithTimeout := &writerWithTimeout{Writer: str, Timeout: time.Second}

	mockSender.EXPECT().onHasStreamData(streamID, str)
	_, err := strWithTimeout.Write([]byte("foobar"))
	require.NoError(t, err)
	mockFC.EXPECT().SendWindowSize().Return(protocol.MaxByteCount)
	mockFC.EXPECT().AddBytesSent(protocol.ByteCount(3))
	frame, _, hasMore := str.popStreamFrame(3+expectedFrameHeaderLen(streamID, 0), protocol.Version1)
	require.NotNil(t, frame.Frame)
	require.True(t, hasMore)
	require.Equal(t, []byte("foo"), frame.Frame.Data)
	require.True(t, mockCtrl.Satisfied())

	wrote := make(chan struct{})
	mockSender.EXPECT().onHasStreamData(streamID, str).Do(func(protocol.StreamID, sendStreamI) { close(wrote) })
	errChan := make(chan error, 1)
	go func() {
		_, err := strWithTimeout.Write(make([]byte, 2000))
		errChan <- err
	}()

	select {
	case <-wrote:
	case <-time.After(time.Second):
		t.Fatal("timeout")
	}

	// cancel the stream
	mockSender.EXPECT().onHasStreamControlFrame(streamID, str)
	str.CancelWrite(1234)
	require.True(t, mockCtrl.Satisfied())

	cf, ok, hasMore := str.getControlFrame(time.Now())
	require.True(t, ok)
	// only the "foo" was sent out, so the final size is 3
	require.Equal(t, &wire.ResetStreamFrame{StreamID: streamID, FinalSize: 3, ErrorCode: 1234}, cf.Frame)
	require.False(t, hasMore)

	// the context was canceled
	select {
	case <-str.Context().Done():
	default:
		t.Fatal("stream context should have been canceled")
	}
	require.ErrorIs(t, context.Cause(str.Context()), &StreamError{StreamID: streamID, ErrorCode: 1234, Remote: false})

	// duplicate calls to CancelWrite don't do anything
	str.CancelWrite(1234)
	_, ok, _ = str.getControlFrame(time.Now())
	require.False(t, ok)

	// the Write call should return an error
	select {
	case err := <-errChan:
		require.ErrorIs(t, err, &StreamError{StreamID: streamID, ErrorCode: 1234, Remote: false})
	case <-time.After(time.Second):
		t.Fatal("timeout")
	}

	// no data to send
	frame, _, hasMore = str.popStreamFrame(protocol.MaxByteCount, protocol.Version1)
	require.Nil(t, frame.Frame)
	require.False(t, hasMore)

	// future calls to Write should return an error
	_, err = strWithTimeout.Write([]byte("foo"))
	require.ErrorIs(t, err, &StreamError{StreamID: streamID, ErrorCode: 1234, Remote: false})
	frame, _, hasMore = str.popStreamFrame(protocol.MaxByteCount, protocol.Version1)
	require.Nil(t, frame.Frame)
	require.False(t, hasMore)

	// Close has no effect
	require.ErrorContains(t, str.Close(), "close called for canceled stream")
	frame, _, _ = str.popStreamFrame(protocol.MaxByteCount, protocol.Version1)
	require.Nil(t, frame.Frame)
	_, err = strWithTimeout.Write([]byte("foobar"))
	require.Error(t, err)
	require.ErrorIs(t, err, &StreamError{StreamID: streamID, ErrorCode: 1234, Remote: false})

	// shutting down has no effect
	str.closeForShutdown(errors.New("goodbyte"))
	_, err = strWithTimeout.Write([]byte("foobar"))
	require.ErrorIs(t, err, &StreamError{StreamID: streamID, ErrorCode: 1234, Remote: false})
}

// It is possible to cancel a stream after it has been closed.
// This is useful if the applications wants to prevent the retransmission of outstanding stream data.
func TestSendStreamCancellationAfterClose(t *testing.T) {
	const streamID protocol.StreamID = 1234
	mockCtrl := gomock.NewController(t)
	mockFC := mocks.NewMockStreamFlowController(mockCtrl)
	mockSender := NewMockStreamSender(mockCtrl)
	str := newSendStream(context.Background(), streamID, mockSender, mockFC)
	strWithTimeout := &writerWithTimeout{Writer: str, Timeout: time.Second}

	mockSender.EXPECT().onHasStreamData(streamID, str).Times(2)
	_, err := strWithTimeout.Write([]byte("foobar"))
	require.NoError(t, err)
	require.NoError(t, str.Close())

	mockSender.EXPECT().onHasStreamControlFrame(streamID, str)
	str.CancelWrite(1337)

	frame, _, hasMore := str.popStreamFrame(protocol.MaxByteCount, protocol.Version1)
	require.Nil(t, frame.Frame)
	require.False(t, hasMore)

	cf, ok, hasMore := str.getControlFrame(time.Now())
	require.True(t, ok)
	require.Equal(t, &wire.ResetStreamFrame{StreamID: streamID, FinalSize: 0, ErrorCode: 1337}, cf.Frame)
	require.False(t, hasMore)

	_, err = strWithTimeout.Write([]byte("foobar"))
	require.Error(t, err)
	require.ErrorIs(t, err, &StreamError{StreamID: streamID, ErrorCode: 1337, Remote: false})
}

func TestSendStreamCancellationStreamRetransmission(t *testing.T) {
	t.Run("local", func(t *testing.T) {
		testSendStreamCancellationStreamRetransmission(t, false)
	})
	t.Run("remote", func(t *testing.T) {
		testSendStreamCancellationStreamRetransmission(t, true)
	})
}

func testSendStreamCancellationStreamRetransmission(t *testing.T, remote bool) {
	const streamID protocol.StreamID = 1000
	mockCtrl := gomock.NewController(t)
	mockFC := mocks.NewMockStreamFlowController(mockCtrl)
	mockSender := NewMockStreamSender(mockCtrl)
	str := newSendStream(context.Background(), streamID, mockSender, mockFC)

	mockSender.EXPECT().onHasStreamData(streamID, str)
	_, err := (&writerWithTimeout{Writer: str, Timeout: time.Second}).Write([]byte("foobar"))
	require.NoError(t, err)

	mockFC.EXPECT().SendWindowSize().Return(protocol.MaxByteCount).Times(2)
	mockFC.EXPECT().AddBytesSent(protocol.ByteCount(3)).Times(2)
	f1, _, hasMore := str.popStreamFrame(3+expectedFrameHeaderLen(streamID, 0), protocol.Version1)
	require.NotNil(t, f1.Frame)
	require.True(t, hasMore)
	f2, _, hasMore := str.popStreamFrame(3+expectedFrameHeaderLen(streamID, 3), protocol.Version1)
	require.NotNil(t, f2.Frame)
	require.False(t, hasMore)

	mockSender.EXPECT().onHasStreamControlFrame(streamID, str)
	if remote {
		str.handleStopSendingFrame(&wire.StopSendingFrame{StreamID: streamID, ErrorCode: 1337})
	} else {
		str.CancelWrite(1337)
	}
	cf, ok, hasMore := str.getControlFrame(time.Now())
	require.True(t, ok)
	require.IsType(t, &wire.ResetStreamFrame{}, cf.Frame)
	require.False(t, hasMore)

	// it doesn't matter if the STREAM frames are acked or lost
	f1.Handler.OnAcked(f1.Frame)
	f2.Handler.OnLost(f2.Frame)
	frame, _, hasMore := str.popStreamFrame(protocol.MaxByteCount, protocol.Version1)
	require.Nil(t, frame.Frame)
	require.False(t, hasMore)
	// if CancelWrite was called, the stream is completed as soon as the RESET_STREAM frame is acked
	if !remote {
		mockSender.EXPECT().onStreamCompleted(streamID)
	}
	cf.Handler.OnAcked(cf.Frame)

	// but if it's a remote cancellation, the application has to consume the error first
	if remote {
		mockSender.EXPECT().onStreamCompleted(streamID)
		_, err := str.Write([]byte("foobar"))
		require.ErrorIs(t, err, &StreamError{StreamID: streamID, ErrorCode: 1337, Remote: true})
	}
}

func TestSendStreamCancellationResetStreamRetransmission(t *testing.T) {
	const streamID protocol.StreamID = 1000
	mockCtrl := gomock.NewController(t)
	mockFC := mocks.NewMockStreamFlowController(mockCtrl)
	mockSender := NewMockStreamSender(mockCtrl)
	str := newSendStream(context.Background(), streamID, mockSender, mockFC)

	mockSender.EXPECT().onHasStreamControlFrame(streamID, str)
	str.CancelWrite(1337)

	f1, ok, hasMore := str.getControlFrame(time.Now())
	require.True(t, ok)
	require.Equal(t, &wire.ResetStreamFrame{StreamID: streamID, FinalSize: 0, ErrorCode: 1337}, f1.Frame)
	require.False(t, hasMore)
	require.True(t, mockCtrl.Satisfied())

	// lose the RESET_STREAM frame
	mockSender.EXPECT().onHasStreamControlFrame(streamID, str)
	f1.Handler.OnLost(f1.Frame)
	// get the retransmission
	f2, ok, hasMore := str.getControlFrame(time.Now())
	require.True(t, ok)
	require.Equal(t, &wire.ResetStreamFrame{StreamID: streamID, FinalSize: 0, ErrorCode: 1337}, f2.Frame)
	require.False(t, hasMore)
	require.True(t, mockCtrl.Satisfied())

	// acknowledging the RESET_STREAM frame completes the stream
	mockSender.EXPECT().onStreamCompleted(streamID)
	f2.Handler.OnAcked(f2.Frame)
}

func TestSendStreamStopSending(t *testing.T) {
	const streamID protocol.StreamID = 1000
	mockCtrl := gomock.NewController(t)
	mockFC := mocks.NewMockStreamFlowController(mockCtrl)
	mockSender := NewMockStreamSender(mockCtrl)
	str := newSendStream(context.Background(), streamID, mockSender, mockFC)

	mockSender.EXPECT().onHasStreamData(streamID, str).MaxTimes(2)
	_, err := (&writerWithTimeout{Writer: str, Timeout: time.Second}).Write([]byte("foobar"))
	require.NoError(t, err)
	mockFC.EXPECT().SendWindowSize().Return(protocol.MaxByteCount)
	mockFC.EXPECT().AddBytesSent(gomock.Any())
	frame, _, _ := str.popStreamFrame(protocol.MaxByteCount, protocol.Version1)
	require.NotNil(t, frame.Frame)
	require.True(t, mockCtrl.Satisfied())

	errChan := make(chan error, 1)
	go func() {
		_, err := (&writerWithTimeout{Writer: str, Timeout: time.Second}).Write(make([]byte, 2000))
		errChan <- err
	}()

	mockSender.EXPECT().onHasStreamControlFrame(streamID, str)
	str.handleStopSendingFrame(&wire.StopSendingFrame{StreamID: streamID, ErrorCode: 1337})

	select {
	case err := <-errChan:
		require.ErrorIs(t, err, &StreamError{StreamID: streamID, ErrorCode: 1337, Remote: true})
	case <-time.After(time.Second):
		t.Fatal("timeout")
	}

	cf, ok, hasMore := str.getControlFrame(time.Now())
	require.True(t, ok)
	require.Equal(t, &wire.ResetStreamFrame{StreamID: streamID, FinalSize: 6, ErrorCode: 1337}, cf.Frame)
	require.False(t, hasMore)

	// calls to Write should return an error
	_, err = (&writerWithTimeout{Writer: str, Timeout: time.Second}).Write([]byte("foobar"))
	require.ErrorIs(t, err, &StreamError{StreamID: streamID, ErrorCode: 1337, Remote: true})
	frame, _, _ = str.popStreamFrame(protocol.MaxByteCount, protocol.Version1)
	require.Nil(t, frame.Frame)

	// calls to CancelWrite have no effect
	str.CancelWrite(1234)
	_, err = (&writerWithTimeout{Writer: str, Timeout: time.Second}).Write([]byte("foobar"))
	// error code and remote flag are unchanged
	require.ErrorIs(t, err, &StreamError{StreamID: streamID, ErrorCode: 1337, Remote: true})
	_, ok, _ = str.getControlFrame(time.Now())
	require.False(t, ok)

	// Close has no effect
	require.ErrorContains(t, str.Close(), "close called for canceled stream")
	frame, _, _ = str.popStreamFrame(protocol.MaxByteCount, protocol.Version1)
	require.Nil(t, frame.Frame)
	_, err = (&writerWithTimeout{Writer: str, Timeout: time.Second}).Write([]byte("foobar"))
	require.Error(t, err)
	require.ErrorIs(t, err, &StreamError{StreamID: streamID, ErrorCode: 1337, Remote: true})
}

// This test is inherently racy, as it tests a concurrent call to Write() and CancelRead().
// A single successful run of this test therefore doesn't mean a lot,
// for reliable results it has to be run many times.
func TestSendStreamConcurrentWriteAndCancel(t *testing.T) {
	const streamID protocol.StreamID = 1000
	mockCtrl := gomock.NewController(t)
	mockFC := mocks.NewMockStreamFlowController(mockCtrl)
	mockSender := NewMockStreamSender(mockCtrl)
	str := newSendStream(context.Background(), streamID, mockSender, mockFC)

	mockSender.EXPECT().onHasStreamControlFrame(gomock.Any(), gomock.Any()).MaxTimes(1)
	mockSender.EXPECT().onHasStreamData(streamID, str).MaxTimes(1)
	mockSender.EXPECT().onStreamCompleted(streamID).MaxTimes(1)
	mockFC.EXPECT().SendWindowSize().Return(protocol.MaxByteCount).MaxTimes(1)
	mockFC.EXPECT().AddBytesSent(gomock.Any()).MaxTimes(1)

	errChan := make(chan error, 1)
	go func() {
		n, err := (&writerWithTimeout{Writer: str, Timeout: time.Second}).Write(make([]byte, 100))
		if n == 0 {
			errChan <- nil
			return
		}
		errChan <- err
	}()

	done := make(chan struct{}, 2)
	go func() {
		str.popStreamFrame(protocol.MaxByteCount, protocol.Version1)
		done <- struct{}{}
	}()
	go func() {
		str.CancelWrite(1234)
		done <- struct{}{}
	}()

	select {
	case err := <-errChan:
		require.NoError(t, err)
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for write to complete")
	}

	for i := 0; i < 2; i++ {
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatal("timeout waiting for cancel to complete")
		}
	}
}

func TestSendStreamRetransmissions(t *testing.T) {
	const streamID protocol.StreamID = 1000
	mockCtrl := gomock.NewController(t)
	mockFC := mocks.NewMockStreamFlowController(mockCtrl)
	mockSender := NewMockStreamSender(mockCtrl)
	str := newSendStream(context.Background(), streamID, mockSender, mockFC)

	mockSender.EXPECT().onHasStreamData(streamID, str)
	_, err := str.Write([]byte("foo"))
	require.NoError(t, err)

	mockFC.EXPECT().SendWindowSize().Return(protocol.MaxByteCount)
	mockFC.EXPECT().AddBytesSent(protocol.ByteCount(3))
	f1, _, _ := str.popStreamFrame(protocol.MaxByteCount, protocol.Version1)
	require.EqualExportedValues(t,
		&wire.StreamFrame{StreamID: streamID, Data: []byte("foo"), DataLenPresent: true},
		f1.Frame,
	)
	require.True(t, mockCtrl.Satisfied())

	// write some more data
	mockSender.EXPECT().onHasStreamData(streamID, str).Times(2)
	_, err = (&writerWithTimeout{Writer: str, Timeout: time.Second}).Write([]byte("bar"))
	require.NoError(t, err)
	require.NoError(t, str.Close())
	require.True(t, mockCtrl.Satisfied())

	// lose the frame
	mockSender.EXPECT().onHasStreamData(streamID, str)
	f1.Handler.OnLost(f1.Frame)
	require.True(t, mockCtrl.Satisfied())

	// when popping a new frame, we first get the retransmission...
	f2, _, hasMoreData := str.popStreamFrame(protocol.MaxByteCount, protocol.Version1)
	require.EqualExportedValues(t, &wire.StreamFrame{StreamID: streamID, Data: []byte("foo"), DataLenPresent: true}, f2.Frame)
	require.True(t, hasMoreData)
	require.True(t, mockCtrl.Satisfied())

	// ... then we get the new data
	mockFC.EXPECT().SendWindowSize().Return(protocol.MaxByteCount)
	mockFC.EXPECT().AddBytesSent(protocol.ByteCount(3))
	f3, _, hasMoreData := str.popStreamFrame(protocol.MaxByteCount, protocol.Version1)
	require.EqualExportedValues(t, &wire.StreamFrame{StreamID: streamID, Offset: 3, Fin: true, Data: []byte("bar"), DataLenPresent: true}, f3.Frame)
	require.False(t, hasMoreData)
	require.True(t, mockCtrl.Satisfied())

	// acknowledge the retransmission...
	f2.Handler.OnAcked(f2.Frame)
	// ... and the last frame, which concludes this stream
	mockSender.EXPECT().onStreamCompleted(streamID)
	f3.Handler.OnAcked(f3.Frame)
}

func TestSendStreamRetransmissionFraming(t *testing.T) {
	const streamID protocol.StreamID = 1000
	mockCtrl := gomock.NewController(t)
	mockFC := mocks.NewMockStreamFlowController(mockCtrl)
	mockSender := NewMockStreamSender(mockCtrl)
	str := newSendStream(context.Background(), streamID, mockSender, mockFC)

	mockSender.EXPECT().onHasStreamData(streamID, str)
	_, err := (&writerWithTimeout{Writer: str, Timeout: time.Second}).Write([]byte("foobar"))
	require.NoError(t, err)

	mockFC.EXPECT().SendWindowSize().Return(protocol.MaxByteCount)
	mockFC.EXPECT().AddBytesSent(protocol.ByteCount(6))
	f, _, _ := str.popStreamFrame(protocol.MaxByteCount, protocol.Version1)
	require.NotNil(t, f.Frame)

	// lose the frame
	mockSender.EXPECT().onHasStreamData(streamID, str)
	f.Handler.OnLost(f.Frame)

	// retransmission doesn't fit
	f, _, hasMore := str.popStreamFrame(expectedFrameHeaderLen(streamID, 0), protocol.Version1)
	require.Nil(t, f.Frame)
	require.True(t, hasMore)

	// split the retransmission
	r1, _, hasMore := str.popStreamFrame(expectedFrameHeaderLen(streamID, 0)+3, protocol.Version1)
	require.True(t, hasMore)
	require.EqualExportedValues(t,
		&wire.StreamFrame{StreamID: streamID, Data: []byte("foo"), DataLenPresent: true},
		r1.Frame,
	)
	r2, _, hasMore := str.popStreamFrame(expectedFrameHeaderLen(streamID, 3)+3, protocol.Version1)
	require.True(t, hasMore)
	// When popping a retransmission, we always claim that there's more data to send.
	// We accept that this might be incorrect.
	require.True(t, hasMore)
	require.EqualExportedValues(t,
		&wire.StreamFrame{StreamID: streamID, Offset: 3, Data: []byte("bar"), DataLenPresent: true},
		r2.Frame,
	)
	_, _, hasMore = str.popStreamFrame(expectedFrameHeaderLen(streamID, 3)+3, protocol.Version1)
	require.False(t, hasMore)
}

// This test is kind of an integration test.
// It writes 4 MB of data, and pops STREAM frames that sometimes are and sometimes aren't limited by flow control.
// Half of these STREAM frames are then received and their content saved, while the other half is reported lost
// and has to be retransmitted.
func TestSendStreamRetransmitDataUntilAcknowledged(t *testing.T) {
	const streamID protocol.StreamID = 123456
	const dataLen = 1 << 22 // 4 MB
	mockCtrl := gomock.NewController(t)
	mockSender := NewMockStreamSender(mockCtrl)
	mockFC := mocks.NewMockStreamFlowController(mockCtrl)
	str := newSendStream(context.Background(), streamID, mockSender, mockFC)

	mockSender.EXPECT().onHasStreamData(streamID, str).AnyTimes()
	mockFC.EXPECT().SendWindowSize().DoAndReturn(func() protocol.ByteCount {
		return protocol.ByteCount(mrand.IntN(500)) + 50
	}).AnyTimes()
	mockFC.EXPECT().IsNewlyBlocked().Return(false).AnyTimes()
	mockFC.EXPECT().AddBytesSent(gomock.Any()).AnyTimes()

	data := make([]byte, dataLen)
	_, err := rand.Read(data)
	require.NoError(t, err)
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, err := str.Write(data)
		require.NoError(t, err)
		str.Close()
	}()

	var completed bool
	mockSender.EXPECT().onStreamCompleted(streamID).Do(func(protocol.StreamID) { completed = true })

	received := make([]byte, dataLen)
	for !completed {
		f, _, _ := str.popStreamFrame(protocol.ByteCount(mrand.IntN(300)+100), protocol.Version1)
		if f.Frame == nil {
			continue
		}
		sf := f.Frame
		// 50%: acknowledge the frame and save the data
		// 50%: lose the frame
		if mrand.IntN(100) < 50 {
			copy(received[sf.Offset:sf.Offset+sf.DataLen()], sf.Data)
			f.Handler.OnAcked(f.Frame)
		} else {
			f.Handler.OnLost(f.Frame)
		}
	}
	require.Equal(t, data, received)
}
