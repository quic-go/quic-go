package http3

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	mockquic "github.com/quic-go/quic-go/internal/mocks/quic"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

type mockStreamClearer struct {
	cleared *quic.StreamID
}

func (s *mockStreamClearer) clearStream(id quic.StreamID) {
	s.cleared = &id
}

type mockErrorSetter struct {
	sendErrs []error
	recvErrs []error

	sendSent chan struct{}
}

func (e *mockErrorSetter) SetSendError(err error) {
	e.sendErrs = append(e.sendErrs, err)

	if e.sendSent != nil {
		close(e.sendSent)
	}
}

func (e *mockErrorSetter) SetReceiveError(err error) {
	e.recvErrs = append(e.recvErrs, err)
}

func TestStateTrackingStreamRead(t *testing.T) {
	t.Run("io.EOF", func(t *testing.T) {
		testStateTrackingStreamRead(t, io.EOF)
	})
	t.Run("remote stream reset", func(t *testing.T) {
		testStateTrackingStreamRead(t, assert.AnError)
	})
}

func testStateTrackingStreamRead(t *testing.T, expectedErr error) {
	mockCtrl := gomock.NewController(t)
	qstr := mockquic.NewMockStream(mockCtrl)
	qstr.EXPECT().StreamID().AnyTimes().Return(quic.StreamID(1337))
	qstr.EXPECT().Context().Return(context.Background()).AnyTimes()

	var (
		clearer mockStreamClearer
		setter  mockErrorSetter
		str     = newStateTrackingStream(qstr, &clearer, &setter)
	)

	// deadline errors are ignored
	qstr.EXPECT().Read(gomock.Any()).Return(0, os.ErrDeadlineExceeded)
	_, err := str.Read(make([]byte, 3))
	require.ErrorIs(t, err, os.ErrDeadlineExceeded)
	require.Nil(t, clearer.cleared)
	require.Empty(t, setter.recvErrs)
	require.Empty(t, setter.sendErrs)

	if expectedErr == io.EOF {
		buf := bytes.NewBuffer([]byte("foobar"))
		qstr.EXPECT().Read(gomock.Any()).DoAndReturn(buf.Read).AnyTimes()

		for i := 0; i < 3; i++ {
			_, err := str.Read([]byte{0})
			require.NoError(t, err)
			require.Nil(t, clearer.cleared)
			require.Empty(t, setter.recvErrs)
			require.Empty(t, setter.sendErrs)
		}
	} else {
		qstr.EXPECT().Read(gomock.Any()).Return(0, expectedErr).AnyTimes()
	}

	_, err = io.ReadAll(str)
	if expectedErr == io.EOF {
		require.NoError(t, err)
	} else {
		require.ErrorIs(t, err, expectedErr)
	}
	require.Nil(t, clearer.cleared)
	require.Len(t, setter.recvErrs, 1)
	require.Equal(t, expectedErr, setter.recvErrs[0])
	require.Empty(t, setter.sendErrs)
}

func TestStateTrackingStreamWrite(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	qstr := mockquic.NewMockStream(mockCtrl)
	qstr.EXPECT().StreamID().AnyTimes().Return(quic.StreamID(1337))
	qstr.EXPECT().Context().Return(context.Background()).AnyTimes()

	var (
		clearer mockStreamClearer
		setter  mockErrorSetter
		str     = newStateTrackingStream(qstr, &clearer, &setter)
	)

	qstr.EXPECT().Write([]byte("foo")).Return(3, nil)
	qstr.EXPECT().Write([]byte("baz")).Return(0, os.ErrDeadlineExceeded)
	qstr.EXPECT().Write([]byte("bar")).Return(0, assert.AnError)

	_, err := str.Write([]byte("foo"))
	require.NoError(t, err)
	require.Nil(t, clearer.cleared)
	require.Empty(t, setter.recvErrs)
	require.Empty(t, setter.sendErrs)

	// deadline errors are ignored
	_, err = str.Write([]byte("baz"))
	require.ErrorIs(t, err, os.ErrDeadlineExceeded)
	require.Nil(t, clearer.cleared)
	require.Empty(t, setter.recvErrs)
	require.Empty(t, setter.sendErrs)

	_, err = str.Write([]byte("bar"))
	require.ErrorIs(t, err, assert.AnError)
	require.Nil(t, clearer.cleared)
	require.Empty(t, setter.recvErrs)
	require.Len(t, setter.sendErrs, 1)
	require.Equal(t, assert.AnError, setter.sendErrs[0])
}

func TestStateTrackingStreamCancelRead(t *testing.T) {
	const streamID quic.StreamID = 42
	mockCtrl := gomock.NewController(t)
	qstr := mockquic.NewMockStream(mockCtrl)
	qstr.EXPECT().StreamID().AnyTimes().Return(streamID)
	qstr.EXPECT().Context().Return(context.Background()).AnyTimes()

	var (
		clearer mockStreamClearer
		setter  mockErrorSetter
		str     = newStateTrackingStream(qstr, &clearer, &setter)
	)

	buf := bytes.NewBuffer([]byte("foobar"))
	qstr.EXPECT().Read(gomock.Any()).DoAndReturn(buf.Read).AnyTimes()
	qstr.EXPECT().CancelRead(quic.StreamErrorCode(1337))
	_, err := str.Read(make([]byte, 3))
	require.NoError(t, err)
	require.Nil(t, clearer.cleared)
	require.Empty(t, setter.recvErrs)
	require.Empty(t, setter.sendErrs)

	str.CancelRead(1337)
	require.Nil(t, clearer.cleared)
	require.Len(t, setter.recvErrs, 1)
	require.Equal(t, &quic.StreamError{StreamID: streamID, ErrorCode: 1337}, setter.recvErrs[0])
	require.Empty(t, setter.sendErrs)
}

func TestStateTrackingStreamCancelWrite(t *testing.T) {
	const streamID quic.StreamID = 1234
	mockCtrl := gomock.NewController(t)
	qstr := mockquic.NewMockStream(mockCtrl)
	qstr.EXPECT().StreamID().AnyTimes().Return(streamID)
	qstr.EXPECT().Context().Return(context.Background()).AnyTimes()

	var (
		clearer mockStreamClearer
		setter  mockErrorSetter
		str     = newStateTrackingStream(qstr, &clearer, &setter)
	)

	qstr.EXPECT().Write(gomock.Any())
	qstr.EXPECT().CancelWrite(quic.StreamErrorCode(1337))
	_, err := str.Write([]byte("foobar"))
	require.NoError(t, err)
	require.Nil(t, clearer.cleared)
	require.Empty(t, setter.recvErrs)
	require.Empty(t, setter.sendErrs)

	str.CancelWrite(1337)
	require.Nil(t, clearer.cleared)
	require.Empty(t, setter.recvErrs)
	require.Len(t, setter.sendErrs, 1)
	require.Equal(t, &quic.StreamError{StreamID: streamID, ErrorCode: 1337}, setter.sendErrs[0])
}

func TestStateTrackingStreamContext(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	qstr := mockquic.NewMockStream(mockCtrl)
	qstr.EXPECT().StreamID().AnyTimes()
	ctx, cancel := context.WithCancelCause(context.Background())
	qstr.EXPECT().Context().Return(ctx).AnyTimes()

	var (
		clearer mockStreamClearer
		setter  = mockErrorSetter{
			sendSent: make(chan struct{}),
		}
	)

	_ = newStateTrackingStream(qstr, &clearer, &setter)
	require.Nil(t, clearer.cleared)
	require.Empty(t, setter.recvErrs)
	require.Empty(t, setter.sendErrs)

	testErr := errors.New("test error")
	cancel(testErr)
	select {
	case <-setter.sendSent:
	case <-time.After(time.Second):
		t.Fatal("timeout")
	}
	require.Nil(t, clearer.cleared)
	require.Empty(t, setter.recvErrs)
	require.Len(t, setter.sendErrs, 1)
	require.Equal(t, testErr, setter.sendErrs[0])
}

func TestStateTrackingStreamReceiveThenSend(t *testing.T) {
	streamID := quic.StreamID(1234)
	mockCtrl := gomock.NewController(t)
	qstr := mockquic.NewMockStream(mockCtrl)
	qstr.EXPECT().StreamID().AnyTimes().Return(streamID)
	qstr.EXPECT().Context().Return(context.Background()).AnyTimes()

	var (
		clearer mockStreamClearer
		setter  mockErrorSetter
		str     = newStateTrackingStream(qstr, &clearer, &setter)
	)

	buf := bytes.NewBuffer([]byte("foobar"))
	qstr.EXPECT().Read(gomock.Any()).DoAndReturn(buf.Read).AnyTimes()
	_, err := io.ReadAll(str)
	require.NoError(t, err)

	require.Nil(t, clearer.cleared)
	require.Len(t, setter.recvErrs, 1)
	require.Equal(t, io.EOF, setter.recvErrs[0])

	testErr := errors.New("test error")
	qstr.EXPECT().Write([]byte("bar")).Return(0, testErr)

	_, err = str.Write([]byte("bar"))
	require.ErrorIs(t, err, testErr)
	require.Len(t, setter.sendErrs, 1)
	require.Equal(t, testErr, setter.sendErrs[0])

	require.Equal(t, &streamID, clearer.cleared)
}

func TestStateTrackingStreamSendThenReceive(t *testing.T) {
	streamID := quic.StreamID(1337)
	mockCtrl := gomock.NewController(t)
	qstr := mockquic.NewMockStream(mockCtrl)
	qstr.EXPECT().StreamID().AnyTimes().Return(streamID)
	qstr.EXPECT().Context().Return(context.Background()).AnyTimes()

	var (
		clearer mockStreamClearer
		setter  mockErrorSetter
		str     = newStateTrackingStream(qstr, &clearer, &setter)
	)

	testErr := errors.New("test error")
	qstr.EXPECT().Write([]byte("bar")).Return(0, testErr)

	_, err := str.Write([]byte("bar"))
	require.ErrorIs(t, err, testErr)
	require.Nil(t, clearer.cleared)
	require.Len(t, setter.sendErrs, 1)
	require.Equal(t, testErr, setter.sendErrs[0])

	buf := bytes.NewBuffer([]byte("foobar"))
	qstr.EXPECT().Read(gomock.Any()).DoAndReturn(buf.Read).AnyTimes()

	_, err = io.ReadAll(str)
	require.NoError(t, err)
	require.Len(t, setter.recvErrs, 1)
	require.Equal(t, io.EOF, setter.recvErrs[0])

	require.Equal(t, &streamID, clearer.cleared)
}
