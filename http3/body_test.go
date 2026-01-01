package http3

import (
	"bytes"
	"context"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/quic-go/quic-go"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

func TestResponseBodyReading(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	var buf bytes.Buffer
	buf.Write(getDataFrame([]byte("foobar")))
	str := NewMockDatagramStream(mockCtrl)
	str.EXPECT().StreamID().Return(quic.StreamID(42)).AnyTimes()
	str.EXPECT().Read(gomock.Any()).DoAndReturn(buf.Read).AnyTimes()
	reqDone := make(chan struct{})
	rb := newResponseBody(
		newStream(str, nil, nil, func(io.Reader, *headersFrame) error { return nil }, nil),
		-1,
		reqDone,
	)

	data, err := io.ReadAll(rb)
	require.NoError(t, err)
	require.Equal(t, []byte("foobar"), data)
}

func TestResponseBodyReadError(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	str := NewMockDatagramStream(mockCtrl)
	str.EXPECT().StreamID().Return(quic.StreamID(42)).AnyTimes()
	str.EXPECT().Read(gomock.Any()).Return(0, assert.AnError).Times(2)
	reqDone := make(chan struct{})
	rb := newResponseBody(
		newStream(str, nil, nil, func(io.Reader, *headersFrame) error { return nil }, nil),
		-1,
		reqDone,
	)

	_, err := rb.Read([]byte{0})
	require.ErrorIs(t, err, assert.AnError)
	// repeated calls to Read should return the same error
	_, err = rb.Read([]byte{0})
	require.ErrorIs(t, err, assert.AnError)
	select {
	case <-reqDone:
	default:
		t.Fatal("reqDone should be closed")
	}
}

func TestResponseBodyClose(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	str := NewMockDatagramStream(mockCtrl)
	str.EXPECT().StreamID().Return(quic.StreamID(42)).AnyTimes()
	str.EXPECT().CancelRead(quic.StreamErrorCode(ErrCodeRequestCanceled)).Times(2)
	reqDone := make(chan struct{})
	rb := newResponseBody(
		newStream(str, nil, nil, func(io.Reader, *headersFrame) error { return nil }, nil),
		-1,
		reqDone,
	)
	require.NoError(t, rb.Close())
	select {
	case <-reqDone:
	default:
		t.Fatal("reqDone should be closed")
	}

	// multiple calls to Close should be a no-op
	require.NoError(t, rb.Close())
}

func TestResponseBodyConcurrentClose(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	str := NewMockDatagramStream(mockCtrl)
	str.EXPECT().StreamID().Return(quic.StreamID(42)).AnyTimes()
	str.EXPECT().CancelRead(quic.StreamErrorCode(ErrCodeRequestCanceled)).MaxTimes(3)
	reqDone := make(chan struct{})
	rb := newResponseBody(
		newStream(str, nil, nil, func(io.Reader, *headersFrame) error { return nil }, nil),
		-1,
		reqDone,
	)

	for range 3 {
		go rb.Close()
	}
	select {
	case <-reqDone:
	case <-time.After(time.Second):
		t.Fatal("reqDone should be closed")
	}
}

func TestResponseBodyLengthLimiting(t *testing.T) {
	t.Run("along frame boundary", func(t *testing.T) {
		testResponseBodyLengthLimiting(t, true)
	})

	t.Run("in the middle of a frame", func(t *testing.T) {
		testResponseBodyLengthLimiting(t, false)
	})
}

func testResponseBodyLengthLimiting(t *testing.T, alongFrameBoundary bool) {
	var buf bytes.Buffer
	buf.Write(getDataFrame([]byte("foo")))
	buf.Write(getDataFrame([]byte("bar")))

	l := int64(4)
	if alongFrameBoundary {
		l = 3
	}
	mockCtrl := gomock.NewController(t)
	str := NewMockDatagramStream(mockCtrl)
	str.EXPECT().StreamID().Return(quic.StreamID(42)).AnyTimes()
	str.EXPECT().CancelRead(quic.StreamErrorCode(ErrCodeMessageError))
	str.EXPECT().CancelWrite(quic.StreamErrorCode(ErrCodeMessageError))
	str.EXPECT().Read(gomock.Any()).DoAndReturn(buf.Read).AnyTimes()
	rb := newResponseBody(
		newStream(str, nil, nil, func(io.Reader, *headersFrame) error { return nil }, nil),
		l,
		make(chan struct{}),
	)
	data, err := io.ReadAll(rb)
	require.Equal(t, []byte("foobar")[:l], data)
	require.ErrorIs(t, err, errTooMuchData)
	// check that repeated calls to Read also return the right error
	n, err := rb.Read([]byte{0})
	require.Zero(t, n)
	require.ErrorIs(t, err, errTooMuchData)
}

func TestBodyReadRespectsContext(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	str := NewMockDatagramStream(mockCtrl)
	str.EXPECT().StreamID().Return(quic.StreamID(42)).AnyTimes()
	
	block := make(chan struct{})
	// Read blocks until we close the channel
	str.EXPECT().Read(gomock.Any()).DoAndReturn(func([]byte) (int, error) {
		<-block
		return 0, errors.New("stream canceled")
	})

	reqDone := make(chan struct{})
	rb := newResponseBody(
		newStream(str, nil, nil, func(io.Reader, *headersFrame) error { return nil }, nil),
		-1,
		reqDone,
	)

	ctx, cancel := context.WithCancel(context.Background())
	rb.setContext(ctx, false)

	errChan := make(chan error)
	go func() {
		_, err := rb.Read(make([]byte, 10))
		errChan <- err
	}()

	time.Sleep(50 * time.Millisecond) // Ensure Read is blocked
	cancel()
	close(block) // Simulate cancellation unblocking the stream

	select {
	case err := <-errChan:
		// Ensure we get the context error, not the stream error
		require.ErrorIs(t, err, context.Canceled)
	case <-time.After(1 * time.Second):
		t.Fatal("timeout")
	}
}

func TestBodyRead_DontCloseRequestStream(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	str := NewMockDatagramStream(mockCtrl)
	str.EXPECT().StreamID().Return(quic.StreamID(42)).AnyTimes()
	
	var buf bytes.Buffer
	buf.Write(getDataFrame([]byte("data")))
	str.EXPECT().Read(gomock.Any()).DoAndReturn(buf.Read).AnyTimes()

	reqDone := make(chan struct{})
	rb := newResponseBody(
		newStream(str, nil, nil, func(io.Reader, *headersFrame) error { return nil }, nil),
		-1,
		reqDone,
	)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() 
	
	rb.setContext(ctx, true) // Enable DontClose

	n, err := rb.Read(make([]byte, 10))
	require.NoError(t, err)
	require.Equal(t, 4, n)
}
