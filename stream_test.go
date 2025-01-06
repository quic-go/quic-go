package quic

import (
	"context"
	"io"
	"os"
	"testing"
	"time"

	"github.com/quic-go/quic-go/internal/mocks"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/wire"

	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

func TestStreamDeadlines(t *testing.T) {
	const streamID protocol.StreamID = 1337
	mockCtrl := gomock.NewController(t)
	mockSender := NewMockStreamSender(mockCtrl)
	mockFC := mocks.NewMockStreamFlowController(mockCtrl)
	str := newStream(context.Background(), streamID, mockSender, mockFC)

	// SetDeadline sets both read and write deadlines
	str.SetDeadline(time.Now().Add(-time.Second))
	n, err := (&writerWithTimeout{Writer: str, Timeout: time.Second}).Write([]byte("foobar"))
	require.ErrorIs(t, err, os.ErrDeadlineExceeded)
	require.Zero(t, n)

	mockFC.EXPECT().UpdateHighestReceived(protocol.ByteCount(6), false, gomock.Any()).AnyTimes()
	require.NoError(t, str.handleStreamFrame(&wire.StreamFrame{Data: []byte("foobar")}, time.Now()))
	n, err = (&readerWithTimeout{Reader: str, Timeout: time.Second}).Read(make([]byte, 6))
	require.ErrorIs(t, err, os.ErrDeadlineExceeded)
	require.Zero(t, n)
}

func TestStreamCompletion(t *testing.T) {
	completeReadSide := func(
		t *testing.T,
		str *stream,
		mockCtrl *gomock.Controller,
		mockFC *mocks.MockStreamFlowController,
	) {
		t.Helper()
		mockFC.EXPECT().UpdateHighestReceived(protocol.ByteCount(6), true, gomock.Any())
		mockFC.EXPECT().AddBytesRead(protocol.ByteCount(6))
		require.NoError(t, str.handleStreamFrame(&wire.StreamFrame{
			StreamID: str.StreamID(),
			Data:     []byte("foobar"),
			Fin:      true,
		}, time.Now()))
		_, err := (&readerWithTimeout{Reader: str, Timeout: time.Second}).Read(make([]byte, 6))
		require.ErrorIs(t, err, io.EOF)
		require.True(t, mockCtrl.Satisfied())
	}

	completeWriteSide := func(
		t *testing.T,
		str *stream,
		mockCtrl *gomock.Controller,
		mockFC *mocks.MockStreamFlowController,
		mockSender *MockStreamSender,
	) {
		t.Helper()
		mockSender.EXPECT().onHasStreamData(str.StreamID(), gomock.Any()).Times(2)
		_, err := (&writerWithTimeout{Writer: str, Timeout: time.Second}).Write([]byte("foobar"))
		require.NoError(t, err)
		require.NoError(t, str.Close())
		mockFC.EXPECT().SendWindowSize().Return(protocol.MaxByteCount)
		mockFC.EXPECT().AddBytesSent(protocol.ByteCount(6))
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
		mockFC := mocks.NewMockStreamFlowController(mockCtrl)
		str := newStream(context.Background(), streamID, mockSender, mockFC)

		completeReadSide(t, str, mockCtrl, mockFC)
		mockSender.EXPECT().onStreamCompleted(streamID)
		completeWriteSide(t, str, mockCtrl, mockFC, mockSender)
	})

	t.Run("first write, then read", func(t *testing.T) {
		mockCtrl := gomock.NewController(t)
		mockSender := NewMockStreamSender(mockCtrl)
		mockFC := mocks.NewMockStreamFlowController(mockCtrl)
		str := newStream(context.Background(), streamID, mockSender, mockFC)

		completeWriteSide(t, str, mockCtrl, mockFC, mockSender)
		mockSender.EXPECT().onStreamCompleted(streamID)
		completeReadSide(t, str, mockCtrl, mockFC)
	})
}
