package http3

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"os"
	"testing"
	"time"

	"github.com/Noooste/uquic-go"
	mockquic "github.com/Noooste/uquic-go/internal/mocks/quic"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

func canceledCtx() context.Context {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	return ctx
}

func checkDatagramReceive(t *testing.T, str *stateTrackingStream) {
	t.Helper()
	_, err := str.ReceiveDatagram(canceledCtx())
	require.ErrorIs(t, err, context.Canceled)
}

func checkDatagramSend(t *testing.T, str *stateTrackingStream) {
	t.Helper()
	require.NoError(t, str.SendDatagram([]byte("test")))
}

type mockStreamClearer struct {
	cleared *quic.StreamID
}

func (s *mockStreamClearer) clearStream(id quic.StreamID) {
	s.cleared = &id
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

	var clearer mockStreamClearer
	str := newStateTrackingStream(qstr, &clearer, func(b []byte) error { return nil })

	// deadline errors are ignored
	qstr.EXPECT().Read(gomock.Any()).Return(0, os.ErrDeadlineExceeded)
	_, err := str.Read(make([]byte, 3))
	require.ErrorIs(t, err, os.ErrDeadlineExceeded)
	require.Nil(t, clearer.cleared)

	if expectedErr == io.EOF {
		buf := bytes.NewBuffer([]byte("foobar"))
		qstr.EXPECT().Read(gomock.Any()).DoAndReturn(buf.Read).AnyTimes()

		for range 3 {
			_, err := str.Read([]byte{0})
			require.NoError(t, err)
			require.Nil(t, clearer.cleared)
			checkDatagramReceive(t, str)
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
	// the receive side registered the error
	_, err = str.ReceiveDatagram(canceledCtx())
	require.ErrorIs(t, err, expectedErr)
	// the send side is still open
	require.NoError(t, str.SendDatagram([]byte("foo")))
}

func TestStateTrackingStreamWrite(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	qstr := mockquic.NewMockStream(mockCtrl)
	qstr.EXPECT().StreamID().AnyTimes().Return(quic.StreamID(1337))
	qstr.EXPECT().Context().Return(context.Background()).AnyTimes()

	var clearer mockStreamClearer
	str := newStateTrackingStream(qstr, &clearer, func(b []byte) error { return nil })

	qstr.EXPECT().Write([]byte("foo")).Return(3, nil)
	qstr.EXPECT().Write([]byte("baz")).Return(0, os.ErrDeadlineExceeded)
	qstr.EXPECT().Write([]byte("bar")).Return(0, assert.AnError)

	_, err := str.Write([]byte("foo"))
	require.NoError(t, err)
	require.Nil(t, clearer.cleared)
	checkDatagramReceive(t, str)
	checkDatagramSend(t, str)

	// deadline errors are ignored
	_, err = str.Write([]byte("baz"))
	require.ErrorIs(t, err, os.ErrDeadlineExceeded)
	require.Nil(t, clearer.cleared)
	checkDatagramReceive(t, str)
	checkDatagramSend(t, str)

	_, err = str.Write([]byte("bar"))
	require.ErrorIs(t, err, assert.AnError)
	require.Nil(t, clearer.cleared)
	checkDatagramReceive(t, str)
	require.ErrorIs(t, str.SendDatagram([]byte("test")), assert.AnError)
}

func TestStateTrackingStreamCancelRead(t *testing.T) {
	const streamID quic.StreamID = 42
	mockCtrl := gomock.NewController(t)
	qstr := mockquic.NewMockStream(mockCtrl)
	qstr.EXPECT().StreamID().AnyTimes().Return(streamID)
	qstr.EXPECT().Context().Return(context.Background()).AnyTimes()

	var clearer mockStreamClearer
	str := newStateTrackingStream(qstr, &clearer, func(b []byte) error { return nil })

	buf := bytes.NewBuffer([]byte("foobar"))
	qstr.EXPECT().Read(gomock.Any()).DoAndReturn(buf.Read).AnyTimes()
	qstr.EXPECT().CancelRead(quic.StreamErrorCode(1337))
	_, err := str.Read(make([]byte, 3))
	require.NoError(t, err)
	require.Nil(t, clearer.cleared)
	checkDatagramReceive(t, str)
	checkDatagramSend(t, str)

	str.CancelRead(1337)
	require.Nil(t, clearer.cleared)
	_, err = str.ReceiveDatagram(canceledCtx())
	require.ErrorIs(t, err, &quic.StreamError{StreamID: streamID, ErrorCode: 1337})
	checkDatagramSend(t, str)
}

func TestStateTrackingStreamCancelWrite(t *testing.T) {
	const streamID quic.StreamID = 1234
	mockCtrl := gomock.NewController(t)
	qstr := mockquic.NewMockStream(mockCtrl)
	qstr.EXPECT().StreamID().AnyTimes().Return(streamID)
	qstr.EXPECT().Context().Return(context.Background()).AnyTimes()

	var clearer mockStreamClearer
	str := newStateTrackingStream(qstr, &clearer, func(b []byte) error { return nil })

	qstr.EXPECT().Write(gomock.Any())
	qstr.EXPECT().CancelWrite(quic.StreamErrorCode(1337))
	_, err := str.Write([]byte("foobar"))
	require.NoError(t, err)
	require.Nil(t, clearer.cleared)
	checkDatagramReceive(t, str)
	checkDatagramSend(t, str)

	str.CancelWrite(1337)
	require.Nil(t, clearer.cleared)
	checkDatagramReceive(t, str)
	require.ErrorIs(t, str.SendDatagram([]byte("test")), &quic.StreamError{StreamID: streamID, ErrorCode: 1337})
}

func TestStateTrackingStreamContext(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	qstr := mockquic.NewMockStream(mockCtrl)
	qstr.EXPECT().StreamID().AnyTimes()
	ctx, cancel := context.WithCancelCause(context.Background())
	qstr.EXPECT().Context().Return(ctx).AnyTimes()

	var clearer mockStreamClearer
	str := newStateTrackingStream(qstr, &clearer, func(b []byte) error { return nil })

	require.Nil(t, clearer.cleared)
	checkDatagramReceive(t, str)
	checkDatagramSend(t, str)

	cancel(assert.AnError)
	require.Eventually(t, func() bool {
		err := str.SendDatagram([]byte("test"))
		if err == nil {
			return false
		}
		require.ErrorIs(t, err, assert.AnError)
		return true
	}, time.Second, scaleDuration(5*time.Millisecond))

	checkDatagramReceive(t, str)
	require.Nil(t, clearer.cleared)
}

func TestStateTrackingStreamReceiveThenSend(t *testing.T) {
	streamID := quic.StreamID(1234)
	mockCtrl := gomock.NewController(t)
	qstr := mockquic.NewMockStream(mockCtrl)
	qstr.EXPECT().StreamID().AnyTimes().Return(streamID)
	qstr.EXPECT().Context().Return(context.Background()).AnyTimes()

	var clearer mockStreamClearer
	str := newStateTrackingStream(qstr, &clearer, func(b []byte) error { return nil })

	buf := bytes.NewBuffer([]byte("foobar"))
	qstr.EXPECT().Read(gomock.Any()).DoAndReturn(buf.Read).AnyTimes()
	_, err := io.ReadAll(str)
	require.NoError(t, err)

	require.Nil(t, clearer.cleared)
	_, err = str.ReceiveDatagram(canceledCtx())
	require.ErrorIs(t, err, io.EOF)

	testErr := errors.New("test error")
	qstr.EXPECT().Write([]byte("bar")).Return(0, testErr)

	_, err = str.Write([]byte("bar"))
	require.ErrorIs(t, err, testErr)
	require.ErrorIs(t, str.SendDatagram([]byte("test")), testErr)

	require.Equal(t, &streamID, clearer.cleared)
}

func TestStateTrackingStreamSendThenReceive(t *testing.T) {
	streamID := quic.StreamID(1337)
	mockCtrl := gomock.NewController(t)
	qstr := mockquic.NewMockStream(mockCtrl)
	qstr.EXPECT().StreamID().AnyTimes().Return(streamID)
	qstr.EXPECT().Context().Return(context.Background()).AnyTimes()

	var clearer mockStreamClearer
	str := newStateTrackingStream(qstr, &clearer, func(b []byte) error { return nil })

	testErr := errors.New("test error")
	qstr.EXPECT().Write([]byte("bar")).Return(0, testErr)

	_, err := str.Write([]byte("bar"))
	require.ErrorIs(t, err, testErr)
	require.Nil(t, clearer.cleared)
	require.ErrorIs(t, str.SendDatagram([]byte("test")), testErr)

	buf := bytes.NewBuffer([]byte("foobar"))
	qstr.EXPECT().Read(gomock.Any()).DoAndReturn(buf.Read).AnyTimes()

	_, err = io.ReadAll(str)
	require.NoError(t, err)
	_, err = str.ReceiveDatagram(canceledCtx())
	require.ErrorIs(t, err, io.EOF)

	require.Equal(t, &streamID, clearer.cleared)
}

func TestDatagramReceiving(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	qstr := mockquic.NewMockStream(mockCtrl)
	qstr.EXPECT().StreamID().AnyTimes().Return(quic.StreamID(1337))
	qstr.EXPECT().Context().Return(context.Background()).AnyTimes()

	str := newStateTrackingStream(qstr, nil, func(b []byte) error { return nil })
	type result struct {
		data []byte
		err  error
	}

	// Receive blocks until a datagram is received
	resultChan := make(chan result)
	go func() {
		defer close(resultChan)
		data, err := str.ReceiveDatagram(context.Background())
		resultChan <- result{data: data, err: err}
	}()

	select {
	case <-time.After(scaleDuration(10 * time.Millisecond)):
	case <-resultChan:
		t.Fatal("should not have received a datagram")
	}
	str.enqueueDatagram([]byte("foobar"))

	select {
	case res := <-resultChan:
		require.NoError(t, res.err)
		require.Equal(t, []byte("foobar"), res.data)
	case <-time.After(time.Second):
		t.Fatal("should have received a datagram")
	}

	// up to 32 datagrams can be queued
	for i := range streamDatagramQueueLen + 1 {
		str.enqueueDatagram([]byte{uint8(i)})
	}
	for i := range streamDatagramQueueLen {
		data, err := str.ReceiveDatagram(context.Background())
		require.NoError(t, err)
		require.Equal(t, []byte{uint8(i)}, data)
	}

	// Receive respects the context
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := str.ReceiveDatagram(ctx)
	require.ErrorIs(t, err, context.Canceled)
}

func TestDatagramSending(t *testing.T) {
	var sendQueue [][]byte
	errors := []error{nil, nil, assert.AnError}
	mockCtrl := gomock.NewController(t)
	qstr := mockquic.NewMockStream(mockCtrl)
	qstr.EXPECT().StreamID().AnyTimes().Return(quic.StreamID(1337))
	qstr.EXPECT().Context().Return(context.Background()).AnyTimes()

	str := newStateTrackingStream(qstr, nil, func(b []byte) error {
		sendQueue = append(sendQueue, b)
		err := errors[0]
		errors = errors[1:]
		return err
	})
	require.NoError(t, str.SendDatagram([]byte("foo")))
	require.NoError(t, str.SendDatagram([]byte("bar")))
	require.ErrorIs(t, str.SendDatagram([]byte("baz")), assert.AnError)
	require.Equal(t, [][]byte{[]byte("foo"), []byte("bar"), []byte("baz")}, sendQueue)

	str.closeSend(net.ErrClosed)
	require.ErrorIs(t, str.SendDatagram([]byte("foobar")), net.ErrClosed)
}
