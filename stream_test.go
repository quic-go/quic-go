package quic

import (
	"context"
	"io"
	"os"
	"testing"
	"time"

	"github.com/quic-go/quic-go/internal/monotime"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/wire"

	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

func TestStreamDeadlines(t *testing.T) {
	const streamID protocol.StreamID = 1337
	mockCtrl := gomock.NewController(t)
	mockSender := NewMockStreamSender(mockCtrl)
	fc := newTestStreamFlowControllerWithSendWindow(streamID, protocol.MaxByteCount)
	str := newStream(context.Background(), streamID, mockSender, fc, false)

	// SetDeadline sets both read and write deadlines
	str.SetDeadline(time.Now().Add(-time.Second))
	n, err := (&writerWithTimeout{Writer: str, Timeout: time.Second}).Write([]byte("foobar"))
	require.ErrorIs(t, err, os.ErrDeadlineExceeded)
	require.Zero(t, n)

	require.NoError(t, str.handleStreamFrame(&wire.StreamFrame{Data: []byte("foobar")}, monotime.Now()))
	n, err = (&readerWithTimeout{Reader: str, Timeout: time.Second}).Read(make([]byte, 6))
	require.ErrorIs(t, err, os.ErrDeadlineExceeded)
	require.Zero(t, n)
}

func TestStreamReceiveFinalSizeCallback(t *testing.T) {
	const streamID protocol.StreamID = 1337
	mockCtrl := gomock.NewController(t)
	mockSender := NewMockStreamSender(mockCtrl)
	fc := newTestStreamFlowControllerWithSendWindow(streamID, protocol.MaxByteCount)
	str := newStream(context.Background(), streamID, mockSender, fc, false)

	require.NoError(t, str.handleStreamFrame(&wire.StreamFrame{Data: []byte("foobar"), Fin: true}, monotime.Now()))

	var size int64
	str.SetReceiveFinalSizeCallback(func(s int64) { size = s })
	require.EqualValues(t, 6, size)
}

func TestStreamResetStreamAtFlowControl(t *testing.T) {
	mockSender := NewMockStreamSender(gomock.NewController(t))
	str := newStream(context.Background(), 1337, mockSender, newTestStreamFlowControllerWithSendWindow(1337, 3), true)
	mockSender.EXPECT().onHasStreamData(protocol.StreamID(1337), gomock.Any()).Times(2)
	mockSender.EXPECT().onHasStreamControlFrame(protocol.StreamID(1337), str)
	_, err := str.Write([]byte("foobar"))
	require.NoError(t, err)
	str.SetReliableBoundary()
	str.CancelWrite(42)
	// the Final Size would exceed the flow control limit
	_, ok, hasMore := str.getControlFrame(monotime.Now())
	require.False(t, ok)
	require.True(t, hasMore)

	str.updateSendWindow(6)
	cf, ok, _ := str.getControlFrame(monotime.Now())
	require.True(t, ok)
	require.Equal(t, &wire.ResetStreamFrame{StreamID: 1337, FinalSize: 6, ErrorCode: 42, ReliableSize: 6}, cf.Frame)
}

func TestStreamCompletion(t *testing.T) {
	completeReadSide := func(
		t *testing.T,
		str *Stream,
		mockCtrl *gomock.Controller,
	) {
		t.Helper()
		require.NoError(t, str.handleStreamFrame(&wire.StreamFrame{
			StreamID: str.StreamID(),
			Data:     []byte("foobar"),
			Fin:      true,
		}, monotime.Now()))
		_, err := (&readerWithTimeout{Reader: str, Timeout: time.Second}).Read(make([]byte, 6))
		require.ErrorIs(t, err, io.EOF)
		require.True(t, mockCtrl.Satisfied())
	}

	completeWriteSide := func(
		t *testing.T,
		str *Stream,
		mockCtrl *gomock.Controller,
		mockSender *MockStreamSender,
	) {
		t.Helper()
		mockSender.EXPECT().onHasStreamData(str.StreamID(), gomock.Any()).Times(2)
		_, err := (&writerWithTimeout{Writer: str, Timeout: time.Second}).Write([]byte("foobar"))
		require.NoError(t, err)
		require.NoError(t, str.Close())
		f, _, _ := str.popStreamFrame(protocol.MaxByteCount, protocol.Version1)
		require.NotNil(t, f.Frame)
		require.True(t, f.Frame.Fin)
		f.Handler.OnAcked(f.Frame)
		require.True(t, mockCtrl.Satisfied())
	}

	const streamID protocol.StreamID = 1337

	t.Run("first read, then write", func(t *testing.T) {
		mockCtrl := gomock.NewController(t)
		mockSender := NewMockStreamSender(mockCtrl)
		fc := newTestStreamFlowControllerWithSendWindow(streamID, protocol.MaxByteCount)
		str := newStream(context.Background(), streamID, mockSender, fc, false)

		completeReadSide(t, str, mockCtrl)
		mockSender.EXPECT().onStreamCompleted(streamID)
		completeWriteSide(t, str, mockCtrl, mockSender)
	})

	t.Run("first write, then read", func(t *testing.T) {
		mockCtrl := gomock.NewController(t)
		mockSender := NewMockStreamSender(mockCtrl)
		fc := newTestStreamFlowControllerWithSendWindow(streamID, protocol.MaxByteCount)
		str := newStream(context.Background(), streamID, mockSender, fc, false)

		completeWriteSide(t, str, mockCtrl, mockSender)
		mockSender.EXPECT().onStreamCompleted(streamID)
		completeReadSide(t, str, mockCtrl)
	})
}
