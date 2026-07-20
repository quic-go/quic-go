package quic

import (
	"fmt"
	"io"
	"os"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/quic-go/quic-go/internal/monotime"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/utils"
	"github.com/quic-go/quic-go/internal/wire"

	"github.com/stretchr/testify/assert"
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

type peeker interface {
	Peek(b []byte) (int, error)
}

type peekerWithTimeout struct {
	Peeker  peeker
	Timeout time.Duration
}

func (p *peekerWithTimeout) Peek(b []byte) (n int, err error) {
	done := make(chan struct{})
	go func() {
		defer close(done)
		n, err = p.Peeker.Peek(b)
	}()

	select {
	case <-done:
		return n, err
	case <-time.After(p.Timeout):
		return 0, fmt.Errorf("peek timeout after %s", p.Timeout)
	}
}

func TestReceiveStreamReadData(t *testing.T) {
	mockFC := newTestStreamFlowController(42)
	str := newReceiveStream(42, nil, mockFC)

	// read an entire frame
	now := monotime.Now()
	require.NoError(t, str.handleStreamFrame(&wire.StreamFrame{Data: []byte{0xde, 0xad, 0xbe, 0xef}}, now))
	b := make([]byte, 4)
	n, err := (&readerWithTimeout{Reader: str, Timeout: time.Second}).Read(b)
	require.NoError(t, err)
	require.Equal(t, 4, n)
	require.Equal(t, []byte{0xde, 0xad, 0xbe, 0xef}, b)

	// split a frame across multiple reads
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
	require.NoError(t, str.handleStreamFrame(&wire.StreamFrame{Offset: 8, Data: []byte{'f', 'o', 'o'}}, now))
	require.NoError(t, str.handleStreamFrame(&wire.StreamFrame{Offset: 11, Data: []byte{'b', 'a', 'r'}}, now))
	b = make([]byte, 6)
	n, err = (&readerWithTimeout{Reader: str, Timeout: time.Second}).Read(b)
	require.NoError(t, err)
	require.Equal(t, 6, n)
	require.Equal(t, []byte{'f', 'o', 'o', 'b', 'a', 'r'}, b)

	// reordered frames
	require.NoError(t, str.handleStreamFrame(&wire.StreamFrame{Offset: 17, Data: []byte{'b', 'a', 'z'}}, now))
	require.NoError(t, str.handleStreamFrame(&wire.StreamFrame{Offset: 14, Data: []byte{'f', 'o', 'o'}}, now))
	b = make([]byte, 6)
	n, err = (&readerWithTimeout{Reader: str, Timeout: time.Second}).Read(b)
	require.NoError(t, err)
	require.Equal(t, 6, n)
	require.Equal(t, []byte{'f', 'o', 'o', 'b', 'a', 'z'}, b)
}

func TestReceiveStreamPeekData(t *testing.T) {
	mockFC := newTestStreamFlowController(42)
	str := newReceiveStream(42, nil, mockFC)
	require.NoError(t, str.handleStreamFrame(&wire.StreamFrame{Data: []byte("foo")}, monotime.Now()))
	b := make([]byte, 2)
	n, err := (&peekerWithTimeout{Peeker: str, Timeout: time.Second}).Peek(b)
	require.NoError(t, err)
	require.Equal(t, 2, n)
	require.Equal(t, []byte("fo"), b)

	require.NoError(t, str.handleStreamFrame(&wire.StreamFrame{Data: []byte("bar"), Offset: 3}, monotime.Now()))
	b = make([]byte, 6)
	n, err = (&peekerWithTimeout{Peeker: str, Timeout: time.Second}).Peek(b)
	require.NoError(t, err)
	require.Equal(t, 6, n)
	require.Equal(t, []byte("foobar"), b)

	_, err = str.Read([]byte{0, 0})
	require.NoError(t, err)

	b = make([]byte, 2)
	n, err = (&peekerWithTimeout{Peeker: str, Timeout: time.Second}).Peek(b)
	require.NoError(t, err)
	require.Equal(t, 2, n)
	require.Equal(t, []byte("ob"), b)
	b = make([]byte, 4)
	n, err = (&peekerWithTimeout{Peeker: str, Timeout: time.Second}).Peek(b)
	require.NoError(t, err)
	require.Equal(t, 4, n)
	require.Equal(t, []byte("obar"), b)
}

func TestReceiveStreamBlockRead(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		mockCtrl := gomock.NewController(t)
		mockFC := newTestStreamFlowController(42)
		mockSender := NewMockStreamSender(mockCtrl)
		str := newReceiveStream(42, mockSender, mockFC)

		errChan := make(chan error, 1)
		start := monotime.Now()
		go func() {
			frame := &wire.StreamFrame{Data: []byte{0xde, 0xad}}
			time.Sleep(time.Hour)
			errChan <- str.handleStreamFrame(frame, monotime.Now())
		}()

		n, err := (&readerWithTimeout{Reader: str, Timeout: 2 * time.Hour}).Read(make([]byte, 2))
		require.NoError(t, err)
		require.Equal(t, 2, n)
		require.Equal(t, time.Hour, monotime.Since(start))
		require.NoError(t, <-errChan)
	})
}

func TestReceiveStreamBlockPeek(t *testing.T) {
	t.Run("single STREAM frame", func(t *testing.T) {
		testReceiveStreamBlockPeek(t, false)
	})

	t.Run("multiple STREAM frames", func(t *testing.T) {
		testReceiveStreamBlockPeek(t, true)
	})
}

func testReceiveStreamBlockPeek(t *testing.T, smallWrites bool) {
	synctest.Test(t, func(t *testing.T) {
		mockCtrl := gomock.NewController(t)
		mockFC := newTestStreamFlowController(42)
		mockSender := NewMockStreamSender(mockCtrl)
		str := newReceiveStream(42, mockSender, mockFC)

		errChan := make(chan error, 2)
		start := monotime.Now()
		go func() {
			if smallWrites {
				time.Sleep(30 * time.Minute)
				errChan <- str.handleStreamFrame(&wire.StreamFrame{Data: []byte("foo")}, monotime.Now())
				time.Sleep(30 * time.Minute)
				errChan <- str.handleStreamFrame(&wire.StreamFrame{Offset: 3, Data: []byte("bar")}, monotime.Now())
			} else {
				time.Sleep(time.Hour)
				errChan <- str.handleStreamFrame(&wire.StreamFrame{Data: []byte("foobar")}, monotime.Now())
			}
		}()

		b := make([]byte, 6)
		n, err := (&peekerWithTimeout{Peeker: str, Timeout: 2 * time.Hour}).Peek(b)
		require.NoError(t, err)
		require.Equal(t, 6, n)
		require.Equal(t, []byte("foobar"), b)
		require.Equal(t, time.Hour, monotime.Since(start))
		require.NoError(t, <-errChan)
		if smallWrites {
			require.NoError(t, <-errChan)
		}
	})
}

func TestReceiveStreamReadOverlappingData(t *testing.T) {
	mockFC := newTestStreamFlowController(42)
	str := newReceiveStream(42, nil, mockFC)

	// receive the same frame multiple times
	now := monotime.Now()
	for range 3 {
		require.NoError(t, str.handleStreamFrame(&wire.StreamFrame{Data: []byte{0xde, 0xad, 0xbe, 0xef}}, now))
	}
	b := make([]byte, 4)
	n, err := (&readerWithTimeout{Reader: str, Timeout: time.Second}).Read(b)
	require.NoError(t, err)
	require.Equal(t, 4, n)
	require.Equal(t, []byte{0xde, 0xad, 0xbe, 0xef}, b)

	// receive overlapping data
	require.NoError(t, str.handleStreamFrame(&wire.StreamFrame{Offset: 4, Data: []byte("foob")}, now))
	require.NoError(t, str.handleStreamFrame(&wire.StreamFrame{Offset: 6, Data: []byte("obar")}, now))
	b = make([]byte, 6)
	n, err = (&readerWithTimeout{Reader: str, Timeout: time.Second}).Read(b)
	require.NoError(t, err)
	require.Equal(t, 6, n)
	require.Equal(t, []byte("foobar"), b)
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
	streamReceiveWindow := protocol.MaxByteCount
	connReceiveWindow := protocol.MaxByteCount
	if hasStreamWindowUpdate {
		streamReceiveWindow = 4
	}
	if hasConnWindowUpdate {
		connReceiveWindow = 4
	}
	mockFC := newTestStreamFlowControllerWithWindows(42, 0, streamReceiveWindow, connReceiveWindow)
	mockSender := NewMockStreamSender(mockCtrl)
	str := newReceiveStream(streamID, mockSender, mockFC)

	now := monotime.Now()
	require.NoError(t, str.handleStreamFrame(&wire.StreamFrame{Data: []byte{0xde, 0xad, 0xbe, 0xef}}, now))

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
		f, ok, hasMore := str.getControlFrame(now)
		require.True(t, ok)
		require.Equal(t, &wire.MaxStreamDataFrame{StreamID: streamID, MaximumStreamData: protocol.ByteCount(n) + streamReceiveWindow}, f.Frame)
		require.False(t, hasMore)
	}
	if hasConnWindowUpdate {
		_, ok, hasMore := str.getControlFrame(now)
		require.False(t, ok)
		require.False(t, hasMore)
	}
}

func TestReceiveStreamDeadlineInThePast(t *testing.T) {
	t.Run("read", func(t *testing.T) {
		testReceiveStreamDeadlineInThePast(t, true, func(str *ReceiveStream, b []byte) (int, error) {
			return str.Read(b)
		})
	})
	t.Run("peek", func(t *testing.T) {
		testReceiveStreamDeadlineInThePast(t, false, func(str *ReceiveStream, b []byte) (int, error) {
			return str.Peek(b)
		})
	})
}

func testReceiveStreamDeadlineInThePast(t *testing.T, consumesBytes bool, op func(*ReceiveStream, []byte) (int, error)) {
	mockFC := newTestStreamFlowController(42)
	str := newReceiveStream(42, nil, mockFC)

	// no data is read when the deadline is in the past
	require.NoError(t, str.handleStreamFrame(&wire.StreamFrame{Data: []byte("foobar")}, monotime.Now()))
	require.NoError(t, str.SetReadDeadline(time.Now().Add(-time.Second)))
	b := make([]byte, 6)
	n, err := op(str, b)
	require.Error(t, err)
	require.Zero(t, n)
	require.ErrorIs(t, err, errDeadline)

	// data is read when the deadline is in the future
	require.NoError(t, str.SetReadDeadline(time.Now().Add(time.Second)))
	n, err = op(str, b)
	require.NoError(t, err)
	require.Equal(t, 6, n)
}

func TestReceiveStreamDeadlineRemoval(t *testing.T) {
	t.Run("read", func(t *testing.T) {
		testReceiveStreamDeadlineRemoval(t, func(str *ReceiveStream) error {
			_, err := str.Read([]byte{0})
			return err
		})
	})
	t.Run("peek", func(t *testing.T) {
		testReceiveStreamDeadlineRemoval(t, func(str *ReceiveStream) error {
			_, err := str.Peek([]byte{0})
			return err
		})
	})
}

func testReceiveStreamDeadlineRemoval(t *testing.T, op func(*ReceiveStream) error) {
	synctest.Test(t, func(t *testing.T) {
		mockFC := newTestStreamFlowController(42)
		str := newReceiveStream(42, nil, mockFC)

		const deadline = time.Minute
		require.NoError(t, str.SetReadDeadline(time.Now().Add(deadline)))
		errChan := make(chan error, 1)
		go func() {
			errChan <- op(str)
		}()
		select {
		case err := <-errChan:
			t.Fatalf("should not have returned yet: %v", err)
		case <-time.After(deadline / 2):
		}

		// remove the deadline after a while (but before it expires)
		require.NoError(t, str.SetReadDeadline(time.Time{}))

		// no deadline set: should not return at all
		select {
		case err := <-errChan:
			t.Fatalf("should not have returned yet: %v", err)
		case <-time.After(2 * deadline):
		}

		// now set the deadline to the past to make it return immediately
		require.NoError(t, str.SetReadDeadline(time.Now().Add(-time.Second)))
		synctest.Wait()

		select {
		case err := <-errChan:
			require.ErrorIs(t, err, os.ErrDeadlineExceeded)
		default:
			t.Fatal("timeout")
		}
	})
}

func TestReceiveStreamDeadlineExtension(t *testing.T) {
	t.Run("read", func(t *testing.T) {
		testReceiveStreamDeadlineExtension(t, func(str *ReceiveStream) error {
			_, err := str.Read([]byte{0})
			return err
		})
	})
	t.Run("peek", func(t *testing.T) {
		testReceiveStreamDeadlineExtension(t, func(str *ReceiveStream) error {
			_, err := str.Peek([]byte{0})
			return err
		})
	})
}

func testReceiveStreamDeadlineExtension(t *testing.T, op func(*ReceiveStream) error) {
	synctest.Test(t, func(t *testing.T) {
		mockFC := newTestStreamFlowController(42)
		str := newReceiveStream(42, nil, mockFC)

		start := monotime.Now()
		deadline := 5 * time.Second
		require.NoError(t, str.SetReadDeadline(time.Now().Add(deadline)))
		errChan := make(chan error, 1)
		go func() {
			errChan <- op(str)
		}()
		select {
		case err := <-errChan:
			t.Fatalf("should not have returned yet: %v", err)
		case <-time.After(deadline / 2):
		}

		// extend the deadline
		require.NoError(t, str.SetReadDeadline(time.Now().Add(deadline)))
		select {
		case err := <-errChan:
			require.ErrorIs(t, err, os.ErrDeadlineExceeded)
			require.Equal(t, start.Add(deadline*3/2), monotime.Now())
		case <-time.After(deadline + time.Nanosecond):
			t.Fatal("timeout")
		}
	})
}

func TestReceiveStreamEOFWithData(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	mockFC := newTestStreamFlowController(42)
	mockSender := NewMockStreamSender(mockCtrl)
	str := newReceiveStream(42, mockSender, mockFC)

	now := monotime.Now()
	require.NoError(t, str.handleStreamFrame(&wire.StreamFrame{Offset: 2, Data: []byte{0xbe, 0xef}, Fin: true}, now))
	require.NoError(t, str.handleStreamFrame(&wire.StreamFrame{Data: []byte{0xde, 0xad}}, now))
	mockSender.EXPECT().onStreamCompleted(protocol.StreamID(42))

	// peeking doesn't return an EOF
	b := make([]byte, 4)
	n, err := (&peekerWithTimeout{Peeker: str, Timeout: time.Second}).Peek(b)
	require.NoError(t, err)
	require.Equal(t, 4, n)
	require.Equal(t, []byte{0xde, 0xad, 0xbe, 0xef}, b)

	// peeking returns the EOF, if more data is being peeked
	b = make([]byte, 6)
	n, err = (&peekerWithTimeout{Peeker: str, Timeout: time.Second}).Peek(b)
	require.ErrorIs(t, err, io.EOF)
	require.Equal(t, 4, n)
	require.Equal(t, []byte{0xde, 0xad, 0xbe, 0xef}, b[:n])

	// reading returns the EOF
	strWithTimeout := &readerWithTimeout{Reader: str, Timeout: time.Second}
	b = make([]byte, 6)
	n, err = strWithTimeout.Read(b)
	require.ErrorIs(t, err, io.EOF)
	require.Equal(t, 4, n)
	require.Equal(t, []byte{0xde, 0xad, 0xbe, 0xef}, b[:n])
	n, err = strWithTimeout.Read(b)
	require.Zero(t, n)
	require.ErrorIs(t, err, io.EOF)
}

func TestReceiveStreamPeekEOF(t *testing.T) {
	t.Run("long peek", func(t *testing.T) {
		testReceiveStreamPeekEOF(t, true)
	})
	t.Run("exact peek", func(t *testing.T) {
		testReceiveStreamPeekEOF(t, false)
	})
}

func testReceiveStreamPeekEOF(t *testing.T, longPeek bool) {
	synctest.Test(t, func(t *testing.T) {
		mockCtrl := gomock.NewController(t)
		mockFC := newTestStreamFlowController(42)
		mockSender := NewMockStreamSender(mockCtrl)
		str := newReceiveStream(42, mockSender, mockFC)

		require.NoError(t, str.handleStreamFrame(&wire.StreamFrame{Offset: 3, Data: []byte("bar"), Fin: true}, monotime.Now()))

		type result struct {
			err  error
			data []byte
		}
		resultChan := make(chan result, 1)
		go func() {
			b := make([]byte, 6)
			if longPeek {
				b = make([]byte, 8)
			}
			n, err := (&peekerWithTimeout{Peeker: str, Timeout: time.Hour}).Peek(b)
			resultChan <- result{err: err, data: b[:n]}
		}()

		synctest.Wait()

		select {
		case result := <-resultChan:
			t.Fatalf("peek should not have returned yet: %v", result.err)
		default:
		}

		require.NoError(t, str.handleStreamFrame(&wire.StreamFrame{Data: []byte("f")}, monotime.Now()))

		synctest.Wait()

		select {
		case result := <-resultChan:
			t.Fatalf("peek should not have returned yet: %v", result.err)
		default:
		}

		require.NoError(t, str.handleStreamFrame(&wire.StreamFrame{Data: []byte("oo"), Offset: 1}, monotime.Now()))

		synctest.Wait()

		select {
		case result := <-resultChan:
			if longPeek {
				assert.ErrorIs(t, result.err, io.EOF)
			} else {
				assert.NoError(t, result.err)
			}
			require.Equal(t, []byte("foobar"), result.data)
		default:
			t.Fatal("peek should have returned")
		}
	})
}

func TestReceiveStreamImmediateFINs(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	mockFC := newTestStreamFlowController(42)
	mockSender := NewMockStreamSender(mockCtrl)
	str := newReceiveStream(42, mockSender, mockFC)
	require.NoError(t, str.handleStreamFrame(&wire.StreamFrame{Fin: true}, monotime.Now()))
	mockSender.EXPECT().onStreamCompleted(protocol.StreamID(42))

	// peeking returns the EOF
	n, err := (&peekerWithTimeout{Peeker: str, Timeout: time.Second}).Peek(make([]byte, 4))
	require.ErrorIs(t, err, io.EOF)
	require.Equal(t, 0, n)

	// and so does reading
	n, err = (&readerWithTimeout{Reader: str, Timeout: time.Second}).Read(make([]byte, 4))
	require.Zero(t, n)
	require.ErrorIs(t, err, io.EOF)
}

func TestReceiveStreamFinalSizeCallbackAfterFIN(t *testing.T) {
	fc := newTestStreamFlowController(42)
	str := newReceiveStream(42, nil, fc)

	require.NoError(t, str.handleStreamFrame(&wire.StreamFrame{Data: []byte("foobar"), Fin: true}, monotime.Now()))

	var size int64
	str.SetReceiveFinalSizeCallback(func(s int64) { size = s })
	require.EqualValues(t, 6, size)

	str.closeForShutdown(assert.AnError)
	str.SetReceiveFinalSizeCallback(func(s int64) { size = s })
	require.EqualValues(t, 6, size)
}

func TestReceiveStreamFinalSizeCallbackAfterCancelRead(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	fc := newTestStreamFlowController(42)
	mockSender := NewMockStreamSender(mockCtrl)
	str := newReceiveStream(42, mockSender, fc)

	var size int64
	var called bool
	str.SetReceiveFinalSizeCallback(func(s int64) {
		size, called = s, true
	})
	require.False(t, called)

	mockSender.EXPECT().onHasStreamControlFrame(str.StreamID(), str)
	str.CancelRead(1234)
	require.False(t, called)

	mockSender.EXPECT().onStreamCompleted(protocol.StreamID(42))
	require.NoError(t, str.handleResetStreamFrame(
		&wire.ResetStreamFrame{StreamID: 42, ErrorCode: 4321, FinalSize: 42},
		monotime.Now(),
	))

	require.True(t, called)
	require.EqualValues(t, 42, size)
}

func TestReceiveStreamFinalSizeCallbackRemoved(t *testing.T) {
	str := newReceiveStream(42, nil, newTestStreamFlowController(42))
	str.SetReceiveFinalSizeCallback(func(int64) { t.Fatal("callback called") })
	str.SetReceiveFinalSizeCallback(nil)
	require.NoError(t, str.handleStreamFrame(&wire.StreamFrame{Fin: true}, monotime.Now()))
}

func TestReceiveStreamCloseForShutdown(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		mockCtrl := gomock.NewController(t)
		mockFC := newTestStreamFlowController(42)
		mockSender := NewMockStreamSender(mockCtrl)
		str := newReceiveStream(42, mockSender, mockFC)
		strWithTimeout := &readerWithTimeout{Reader: str, Timeout: time.Minute}

		// Test immediate return of reads
		readErrChan := make(chan error, 1)
		peekErrChan := make(chan error, 1)
		go func() {
			_, err := strWithTimeout.Read([]byte{0})
			readErrChan <- err
		}()
		go func() {
			_, err := (&peekerWithTimeout{Peeker: str, Timeout: time.Minute}).Peek([]byte{0})
			peekErrChan <- err
		}()

		synctest.Wait()

		select {
		case err := <-readErrChan:
			t.Fatalf("read returned before closeForShutdown: %v", err)
		case err := <-peekErrChan:
			t.Fatalf("peek returned before closeForShutdown: %v", err)
		default:
		}

		str.closeForShutdown(assert.AnError)
		synctest.Wait()

		require.NoError(t, str.handleStreamFrame(&wire.StreamFrame{Fin: true}, monotime.Now()))
		str.SetReceiveFinalSizeCallback(func(int64) { t.Fatal("callback called") })

		select {
		case err := <-readErrChan:
			require.ErrorIs(t, err, assert.AnError)
		default:
			t.Fatal("read should have returned")
		}
		select {
		case err := <-peekErrChan:
			require.ErrorIs(t, err, assert.AnError)
		default:
			t.Fatal("peek should have returned")
		}

		// following calls to Peek should return the error
		n, err := (&peekerWithTimeout{Peeker: str, Timeout: time.Minute}).Peek([]byte{0})
		require.Zero(t, n)
		require.ErrorIs(t, err, assert.AnError)

		// following calls to Read should return the error
		n, err = strWithTimeout.Read([]byte{0})
		require.Zero(t, n)
		require.ErrorIs(t, err, assert.AnError)

		// receiving a RESET_STREAM frame after closeForShutdown does nothing
		require.NoError(t, str.handleResetStreamFrame(&wire.ResetStreamFrame{StreamID: 42, ErrorCode: 1234, FinalSize: 42}, monotime.Now()))
		n, err = strWithTimeout.Read([]byte{0})
		require.Zero(t, n)
		require.ErrorIs(t, err, assert.AnError)

		// calling CancelRead after closeForShutdown does nothing
		str.CancelRead(1234)
		n, err = strWithTimeout.Read([]byte{0})
		require.Zero(t, n)
		require.ErrorIs(t, err, assert.AnError)
	})
}

func TestReceiveStreamCancellation(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		mockCtrl := gomock.NewController(t)
		mockFC := newTestStreamFlowController(42)
		mockSender := NewMockStreamSender(mockCtrl)
		str := newReceiveStream(42, mockSender, mockFC)
		strWithTimeout := &readerWithTimeout{Reader: str, Timeout: 2 * time.Second}

		mockSender.EXPECT().onHasStreamControlFrame(str.StreamID(), gomock.Any())
		readErrChan := make(chan error, 1)
		peekErrChan := make(chan error, 1)
		go func() {
			_, err := strWithTimeout.Read([]byte{0})
			readErrChan <- err
		}()
		go func() {
			_, err := (&peekerWithTimeout{Peeker: str, Timeout: 2 * time.Second}).Peek([]byte{0})
			peekErrChan <- err
		}()

		synctest.Wait()

		str.CancelRead(1234)
		// this queues a STOP_SENDING frame
		f, ok, hasMore := str.getControlFrame(monotime.Now())
		require.True(t, ok)
		require.Equal(t, &wire.StopSendingFrame{StreamID: 42, ErrorCode: 1234}, f.Frame)
		require.False(t, hasMore)
		require.True(t, mockCtrl.Satisfied())

		synctest.Wait()

		select {
		case err := <-readErrChan:
			require.ErrorIs(t, err, &StreamError{StreamID: 42, ErrorCode: 1234, Remote: false})
		default:
			t.Fatal("Read was not unblocked")
		}
		select {
		case err := <-peekErrChan:
			require.ErrorIs(t, err, &StreamError{StreamID: 42, ErrorCode: 1234, Remote: false})
		default:
			t.Fatal("Peek was not unblocked")
		}

		// further calls to Peek return the error
		n, err := (&peekerWithTimeout{Peeker: str, Timeout: 2 * time.Second}).Peek([]byte{0})
		require.Zero(t, n)
		require.ErrorIs(t, err, &StreamError{StreamID: 42, ErrorCode: 1234, Remote: false})

		// further Read calls return the error
		n, err = strWithTimeout.Read([]byte{0})
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
		mockSender.EXPECT().onStreamCompleted(protocol.StreamID(42))
		// receive two of them, to make sure onStreamCompleted is not called twice
		require.NoError(t, str.handleStreamFrame(&wire.StreamFrame{Data: []byte("foobar"), Fin: true}, monotime.Now()))
		require.NoError(t, str.handleStreamFrame(&wire.StreamFrame{Data: []byte("foobar"), Fin: true}, monotime.Now()))
		require.True(t, mockCtrl.Satisfied())

		// receiving a RESET_STREAM frame after CancelRead has no effect
		require.NoError(t, str.handleResetStreamFrame(&wire.ResetStreamFrame{StreamID: 42, ErrorCode: 4321, FinalSize: 6}, monotime.Now()))
		n, err = strWithTimeout.Read([]byte{0})
		require.Zero(t, n)
		require.ErrorIs(t, err, &StreamError{StreamID: 42, ErrorCode: 1234, Remote: false})
	})
}

func TestReceiveStreamCancelReadAbandonsUnreadData(t *testing.T) {
	const streamID protocol.StreamID = 42
	mockCtrl := gomock.NewController(t)
	connFC := newConnectionFlowController(6, protocol.MaxByteCount, nil, utils.NewRTTStats(), utils.DefaultLogger)
	fc := newStreamFlowController(
		streamID,
		connFC,
		protocol.MaxByteCount,
		protocol.MaxByteCount,
		0,
		utils.NewRTTStats(),
		utils.DefaultLogger,
	)
	mockSender := NewMockStreamSender(mockCtrl)
	str := newReceiveStream(streamID, mockSender, fc)

	now := monotime.Now()
	require.NoError(t, str.handleStreamFrame(&wire.StreamFrame{Data: []byte("foobar"), Fin: true}, now))
	require.Zero(t, connFC.GetWindowUpdate(now))

	mockSender.EXPECT().onHasStreamControlFrame(streamID, str)
	mockSender.EXPECT().onStreamCompleted(streamID)
	str.CancelRead(1337)
	require.True(t, mockCtrl.Satisfied())

	// CancelRead completes the receive side once the final offset is known.
	// Completion abandons the unread stream data, which returns connection-level
	// flow-control credit and makes a connection window update available.
	require.NotZero(t, connFC.GetWindowUpdate(now))
}

func TestReceiveStreamCancelReadAfterFIN(t *testing.T) {
	t.Run("FIN not read", func(t *testing.T) {
		testReceiveStreamCancelReadAfterFIN(t, false)
	})
	t.Run("FIN read", func(t *testing.T) {
		testReceiveStreamCancelReadAfterFIN(t, true)
	})
}

func testReceiveStreamCancelReadAfterFIN(t *testing.T, finRead bool) {
	mockCtrl := gomock.NewController(t)
	mockFC := newTestStreamFlowController(42)
	mockSender := NewMockStreamSender(mockCtrl)
	str := newReceiveStream(42, mockSender, mockFC)

	mockSender.EXPECT().onStreamCompleted(protocol.StreamID(42))
	require.NoError(t, str.handleStreamFrame(&wire.StreamFrame{Data: []byte("foobar"), Fin: true}, monotime.Now()))
	if finRead {
		n, err := str.Read(make([]byte, 10))
		require.ErrorIs(t, err, io.EOF)
		require.Equal(t, 6, n)
	}

	// if the FIN was received, but not read yet, a STOP_SENDING frame is queued
	if !finRead {
		mockSender.EXPECT().onHasStreamControlFrame(str.StreamID(), str)
	}
	str.CancelRead(1337)
	f, ok, hasMore := str.getControlFrame(monotime.Now())
	// if the EOF was already read, no STOP_SENDING frame is queued
	if finRead {
		require.False(t, ok)
		require.False(t, hasMore)
	} else {
		require.True(t, ok)
		require.Equal(t, &wire.StopSendingFrame{StreamID: 42, ErrorCode: 1337}, f.Frame)
		require.False(t, hasMore)
	}

	// Read returns the error...
	n, err := str.Read([]byte{0})
	require.Zero(t, n)
	// ... and Peek returns the same error
	n, peekErr := (&peekerWithTimeout{Peeker: str, Timeout: time.Second}).Peek([]byte{0})
	require.Zero(t, n)
	if finRead {
		assert.ErrorIs(t, err, io.EOF)
		assert.ErrorIs(t, peekErr, io.EOF)
	} else {
		assert.ErrorIs(t, err, &StreamError{StreamID: 42, ErrorCode: 1337, Remote: false})
		assert.ErrorIs(t, peekErr, &StreamError{StreamID: 42, ErrorCode: 1337, Remote: false})
	}
}

func TestReceiveStreamResetAbandonsUnreadData(t *testing.T) {
	const streamID protocol.StreamID = 42
	mockCtrl := gomock.NewController(t)
	connFC := newConnectionFlowController(6, protocol.MaxByteCount, nil, utils.NewRTTStats(), utils.DefaultLogger)
	fc := newStreamFlowController(
		streamID,
		connFC,
		protocol.MaxByteCount,
		protocol.MaxByteCount,
		0,
		utils.NewRTTStats(),
		utils.DefaultLogger,
	)
	mockSender := NewMockStreamSender(mockCtrl)
	str := newReceiveStream(streamID, mockSender, fc)

	now := monotime.Now()
	require.Zero(t, connFC.GetWindowUpdate(now))
	require.NoError(t, str.handleResetStreamFrame(&wire.ResetStreamFrame{StreamID: streamID, ErrorCode: 1234, FinalSize: 6}, now))

	// A RESET_STREAM with no reliable data abandons the unread final size.
	// That returns connection-level flow-control credit and makes a connection
	// window update available.
	require.NotZero(t, connFC.GetWindowUpdate(now))
}

func TestReceiveStreamReset(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		mockCtrl := gomock.NewController(t)
		mockFC := newTestStreamFlowController(42)
		mockSender := NewMockStreamSender(mockCtrl)
		str := newReceiveStream(42, mockSender, mockFC)
		strWithTimeout := &readerWithTimeout{Reader: str, Timeout: 2 * time.Second}

		readErrChan := make(chan error, 1)
		peekErrChan := make(chan error, 1)
		go func() {
			_, err := strWithTimeout.Read([]byte{0})
			readErrChan <- err
		}()
		go func() {
			_, err := (&peekerWithTimeout{Peeker: str, Timeout: 2 * time.Second}).Peek([]byte{0})
			peekErrChan <- err
		}()

		synctest.Wait()

		mockSender.EXPECT().onStreamCompleted(protocol.StreamID(42))
		require.NoError(t, str.handleResetStreamFrame(
			&wire.ResetStreamFrame{StreamID: 42, ErrorCode: 1234, FinalSize: 42},
			monotime.Now(),
		))

		synctest.Wait()

		select {
		case err := <-readErrChan:
			require.ErrorIs(t, err, &StreamError{StreamID: 42, ErrorCode: 1234, Remote: true})
		default:
			t.Fatal("Read was not unblocked")
		}
		select {
		case err := <-peekErrChan:
			require.ErrorIs(t, err, &StreamError{StreamID: 42, ErrorCode: 1234, Remote: true})
		default:
			t.Fatal("Peek was not unblocked")
		}

		// further calls to Peek return the error
		n, err := (&peekerWithTimeout{Peeker: str, Timeout: 2 * time.Second}).Peek([]byte{0})
		require.Zero(t, n)
		require.ErrorIs(t, err, &StreamError{StreamID: 42, ErrorCode: 1234, Remote: true})

		// further calls to Read return the error
		_, err = strWithTimeout.Read([]byte{0})
		require.Equal(t, &StreamError{StreamID: 42, ErrorCode: 1234, Remote: true}, err)

		// further RESET_STREAM frames have no effect
		require.NoError(t, str.handleResetStreamFrame(
			&wire.ResetStreamFrame{StreamID: 42, ErrorCode: 4321, FinalSize: 42},
			monotime.Now(),
		))

		n, err = str.Read([]byte{0})
		require.Zero(t, n)
		// error code unchanged
		require.ErrorIs(t, err, &StreamError{StreamID: 42, ErrorCode: 1234, Remote: true})

		// CancelRead after a RESET_STREAM frame has no effect
		str.CancelRead(100)
		n, err = str.Read([]byte{0})
		require.Zero(t, n)
		// error code and remote flag unchanged
		require.ErrorIs(t, err, &StreamError{StreamID: 42, ErrorCode: 1234, Remote: true})
	})
}

func TestReceiveStreamResetAfterFINRead(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	mockFC := newTestStreamFlowController(42)
	mockSender := NewMockStreamSender(mockCtrl)
	str := newReceiveStream(42, mockSender, mockFC)
	mockSender.EXPECT().onStreamCompleted(protocol.StreamID(42))
	require.NoError(t, str.handleStreamFrame(
		&wire.StreamFrame{StreamID: 42, Data: []byte("foobar"), Fin: true},
		monotime.Now(),
	))
	n, err := str.Read(make([]byte, 6))
	require.Equal(t, 6, n)
	require.ErrorIs(t, err, io.EOF)
	// make sure that onStreamCompleted was called due to the EOF
	require.True(t, mockCtrl.Satisfied())

	// Now receive a RESET_STREAM frame.
	// We don't expect any more calls to onStreamCompleted.
	require.NoError(t, str.handleResetStreamFrame(
		&wire.ResetStreamFrame{StreamID: 42, ErrorCode: 1234, FinalSize: 6},
		monotime.Now(),
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
	synctest.Test(t, func(t *testing.T) {
		mockCtrl := gomock.NewController(t)
		mockFC := newTestStreamFlowController(42)
		mockSender := NewMockStreamSender(mockCtrl)
		str := newReceiveStream(42, mockSender, mockFC)

		var numCompleted atomic.Int32
		mockSender.EXPECT().onStreamCompleted(protocol.StreamID(42)).Do(func(protocol.StreamID) {
			numCompleted.Add(1)
		}).AnyTimes()

		const num = 3
		resultChan := make(chan struct {
			n   int
			err error
		}, num)
		for range num {
			go func() {
				n, err := str.Read(make([]byte, 8))
				resultChan <- struct {
					n   int
					err error
				}{n: n, err: err}
			}()
		}
		require.NoError(t, str.handleStreamFrame(&wire.StreamFrame{Data: []byte("foobar"), Fin: true}, monotime.Now()))
		synctest.Wait()

		var bytesRead int
		for range num {
			select {
			case res := <-resultChan:
				bytesRead += res.n
				require.ErrorIs(t, res.err, io.EOF)
			default:
				t.Fatal("read should have returned")
			}
		}
		require.Equal(t, 6, bytesRead)
		require.Equal(t, int32(1), numCompleted.Load())
	})
}

func TestReceiveStreamResetStreamAtBeforeReadOffset(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	mockFC := newTestStreamFlowController(42)
	mockSender := NewMockStreamSender(mockCtrl)
	str := newReceiveStream(42, mockSender, mockFC)

	require.NoError(t, str.handleStreamFrame(&wire.StreamFrame{Data: []byte("foobar")}, monotime.Now()))
	b := make([]byte, 3)
	n, err := str.Read(b)
	require.NoError(t, err)
	require.Equal(t, 3, n)
	require.Equal(t, []byte("foo"), b)

	str.handleResetStreamFrame(&wire.ResetStreamFrame{StreamID: 42, ErrorCode: 1337, FinalSize: 10, ReliableSize: 3}, monotime.Now())
	require.True(t, mockCtrl.Satisfied())

	// Peek returns the error
	n, err = str.Peek([]byte{0})
	require.Zero(t, n)
	require.ErrorIs(t, err, &StreamError{StreamID: 42, ErrorCode: 1337, Remote: true})

	// Read returns the error
	mockSender.EXPECT().onStreamCompleted(protocol.StreamID(42))
	n, err = str.Read([]byte{0})
	require.ErrorIs(t, err, &StreamError{StreamID: 42, ErrorCode: 1337, Remote: true})
	require.Zero(t, n)
}

func TestReceiveStreamResetStreamAtAfterReadOffset(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	mockFC := newTestStreamFlowController(42)
	mockSender := NewMockStreamSender(mockCtrl)
	str := newReceiveStream(42, mockSender, mockFC)

	require.NoError(t, str.handleStreamFrame(&wire.StreamFrame{Data: []byte("foobar")}, monotime.Now()))
	b := make([]byte, 2)
	n, err := str.Read(b)
	require.NoError(t, err)
	require.Equal(t, 2, n)
	require.Equal(t, []byte("fo"), b)

	str.handleResetStreamFrame(&wire.ResetStreamFrame{StreamID: 42, ErrorCode: 1337, FinalSize: 10, ReliableSize: 6}, monotime.Now())
	require.True(t, mockCtrl.Satisfied())

	// Peek returns no error when peeking up to the reliable size...
	b = make([]byte, 4)
	n, err = (&peekerWithTimeout{Peeker: str, Timeout: time.Second}).Peek(b)
	require.NoError(t, err)
	require.Equal(t, 4, n)
	require.Equal(t, []byte("obar"), b)

	// ... but returns the error when peeking beyond the reliable size
	b = make([]byte, 5)
	n, err = (&peekerWithTimeout{Peeker: str, Timeout: time.Second}).Peek(b)
	require.ErrorIs(t, err, &StreamError{StreamID: 42, ErrorCode: 1337, Remote: true})
	require.Equal(t, 4, n)
	require.Equal(t, []byte("obar"), b[:n])

	// Read returns the error after reading up to the reliable size
	b = make([]byte, 2)
	n, err = str.Read(b)
	require.NoError(t, err)
	require.Equal(t, 2, n)
	require.Equal(t, []byte("ob"), b)
	require.True(t, mockCtrl.Satisfied())
	mockSender.EXPECT().onStreamCompleted(protocol.StreamID(42))
	n, err = str.Read(b)
	require.ErrorIs(t, err, &StreamError{StreamID: 42, ErrorCode: 1337, Remote: true})
	require.Equal(t, 2, n)
	require.Equal(t, []byte("ar"), b)
}

func TestReceiveStreamMultipleResetStreamAt(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	mockFC := newTestStreamFlowController(42)
	mockSender := NewMockStreamSender(mockCtrl)
	str := newReceiveStream(42, mockSender, mockFC)

	require.NoError(t, str.handleStreamFrame(&wire.StreamFrame{Data: []byte("foobar")}, monotime.Now()))

	b := make([]byte, 3)
	n, err := str.Read(b)
	require.NoError(t, err)
	require.Equal(t, 3, n)
	require.Equal(t, []byte("foo"), b)
	require.True(t, mockCtrl.Satisfied())

	str.handleResetStreamFrame(&wire.ResetStreamFrame{StreamID: 42, ErrorCode: 1337, FinalSize: 10, ReliableSize: 6}, monotime.Now())
	require.True(t, mockCtrl.Satisfied())

	// receiving a reordered RESET_STREAM_AT frame has no effect
	str.handleResetStreamFrame(&wire.ResetStreamFrame{StreamID: 42, ErrorCode: 1337, FinalSize: 10, ReliableSize: 8}, monotime.Now())
	require.True(t, mockCtrl.Satisfied())

	// receiving a RESET_STREAM_AT frame with a smaller reliable size is valid
	str.handleResetStreamFrame(&wire.ResetStreamFrame{StreamID: 42, ErrorCode: 1337, FinalSize: 10, ReliableSize: 3}, monotime.Now())

	// Read returns the error
	mockSender.EXPECT().onStreamCompleted(protocol.StreamID(42))
	n, err = str.Read(b)
	require.ErrorIs(t, err, &StreamError{StreamID: 42, ErrorCode: 1337, Remote: true})
	require.Zero(t, n)
}

func TestReceiveStreamResetStreamAtAfterResetStream(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	mockFC := newTestStreamFlowController(42)
	mockSender := NewMockStreamSender(mockCtrl)
	str := newReceiveStream(42, mockSender, mockFC)

	require.NoError(t, str.handleStreamFrame(&wire.StreamFrame{Data: []byte("foobar")}, monotime.Now()))

	b := make([]byte, 3)
	n, err := str.Read(b)
	require.NoError(t, err)
	require.Equal(t, 3, n)
	require.Equal(t, []byte("foo"), b)
	require.True(t, mockCtrl.Satisfied())

	str.handleResetStreamFrame(&wire.ResetStreamFrame{StreamID: 42, ErrorCode: 1337, FinalSize: 10}, monotime.Now())
	require.True(t, mockCtrl.Satisfied())

	// receiving a reordered RESET_STREAM_AT frame has no effect
	str.handleResetStreamFrame(&wire.ResetStreamFrame{StreamID: 42, ErrorCode: 1337, FinalSize: 10, ReliableSize: 8}, monotime.Now())
	require.True(t, mockCtrl.Satisfied())

	// Read returns the error
	mockSender.EXPECT().onStreamCompleted(protocol.StreamID(42))
	n, err = str.Read(b)
	require.ErrorIs(t, err, &StreamError{StreamID: 42, ErrorCode: 1337, Remote: true})
	require.Zero(t, n)
}
