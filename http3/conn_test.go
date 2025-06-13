package http3

import (
	"bytes"
	"context"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/Noooste/uquic-go"
	mockquic "github.com/Noooste/uquic-go/internal/mocks/quic"
	"github.com/Noooste/uquic-go/internal/protocol"
	"github.com/Noooste/uquic-go/internal/qerr"
	"github.com/Noooste/uquic-go/quicvarint"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

func TestConnReceiveSettings(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	qconn := mockquic.NewMockEarlyConnection(mockCtrl)
	qconn.EXPECT().ReceiveDatagram(gomock.Any()).Return(nil, errors.New("no datagrams")).MaxTimes(1)
	conn := newConnection(
		context.Background(),
		qconn,
		false,
		protocol.PerspectiveServer,
		nil,
		0,
	)
	b := quicvarint.Append(nil, streamTypeControlStream)
	b = (&settingsFrame{
		Datagram:        true,
		ExtendedConnect: true,
		Other:           map[uint64]uint64{1337: 42},
	}).Append(b)
	r := bytes.NewReader(b)
	controlStr := mockquic.NewMockStream(mockCtrl)
	controlStr.EXPECT().Read(gomock.Any()).DoAndReturn(r.Read).AnyTimes()
	qconn.EXPECT().AcceptUniStream(gomock.Any()).Return(controlStr, nil)
	qconn.EXPECT().AcceptUniStream(gomock.Any()).Return(nil, errors.New("test done"))
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn.handleUnidirectionalStreams(nil)
	}()
	select {
	case <-conn.ReceivedSettings():
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for settings")
	}
	settings := conn.Settings()
	require.True(t, settings.EnableDatagrams)
	require.True(t, settings.EnableExtendedConnect)
	require.Equal(t, map[uint64]uint64{1337: 42}, settings.Other)
}

func TestConnRejectDuplicateStreams(t *testing.T) {
	t.Run("control stream", func(t *testing.T) {
		testConnRejectDuplicateStreams(t, streamTypeControlStream)
	})
	t.Run("encoder stream", func(t *testing.T) {
		testConnRejectDuplicateStreams(t, streamTypeQPACKEncoderStream)
	})
	t.Run("decoder stream", func(t *testing.T) {
		testConnRejectDuplicateStreams(t, streamTypeQPACKDecoderStream)
	})
}

func testConnRejectDuplicateStreams(t *testing.T, typ uint64) {
	mockCtrl := gomock.NewController(t)
	qconn := mockquic.NewMockEarlyConnection(mockCtrl)
	conn := newConnection(
		context.Background(),
		qconn,
		false,
		protocol.PerspectiveServer,
		nil,
		0,
	)
	b := quicvarint.Append(nil, typ)
	if typ == streamTypeControlStream {
		b = (&settingsFrame{}).Append(b)
	}
	controlStr1 := mockquic.NewMockStream(mockCtrl)
	controlStr1.EXPECT().Read(gomock.Any()).DoAndReturn(bytes.NewReader(b).Read).AnyTimes()
	controlStr2 := mockquic.NewMockStream(mockCtrl)
	controlStr2.EXPECT().Read(gomock.Any()).DoAndReturn(bytes.NewReader(b).Read).AnyTimes()
	done := make(chan struct{})
	closed := make(chan struct{})
	qconn.EXPECT().CloseWithError(qerr.ApplicationErrorCode(ErrCodeStreamCreationError), gomock.Any()).Do(func(qerr.ApplicationErrorCode, string) error {
		close(closed)
		return nil
	})
	qconn.EXPECT().AcceptUniStream(gomock.Any()).Return(controlStr1, nil)
	qconn.EXPECT().AcceptUniStream(gomock.Any()).Return(controlStr2, nil)
	qconn.EXPECT().AcceptUniStream(gomock.Any()).Return(nil, errors.New("test done"))
	go func() {
		defer close(done)
		conn.handleUnidirectionalStreams(nil)
	}()
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for duplicate stream")
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("timeout")
	}
}

func TestConnResetUnknownUniStream(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	qconn := mockquic.NewMockEarlyConnection(mockCtrl)
	conn := newConnection(
		context.Background(),
		qconn,
		false,
		protocol.PerspectiveServer,
		nil,
		0,
	)
	buf := bytes.NewBuffer(quicvarint.Append(nil, 0x1337))
	str := mockquic.NewMockStream(mockCtrl)
	str.EXPECT().Read(gomock.Any()).DoAndReturn(buf.Read).AnyTimes()
	reset := make(chan struct{})
	str.EXPECT().CancelRead(quic.StreamErrorCode(ErrCodeStreamCreationError)).Do(func(quic.StreamErrorCode) { close(reset) })
	qconn.EXPECT().AcceptUniStream(gomock.Any()).Return(str, nil)
	qconn.EXPECT().AcceptUniStream(gomock.Any()).Return(nil, errors.New("test done"))
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn.handleUnidirectionalStreams(nil)
	}()
	select {
	case <-reset:
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for reset")
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("timeout")
	}
}

func TestConnControlStreamFailures(t *testing.T) {
	t.Run("missing SETTINGS", func(t *testing.T) {
		testConnControlStreamFailures(t, (&dataFrame{}).Append(nil), nil, ErrCodeMissingSettings)
	})
	t.Run("frame error", func(t *testing.T) {
		testConnControlStreamFailures(t,
			// 1337 is invalid value for the Extended CONNECT setting
			(&settingsFrame{Other: map[uint64]uint64{settingExtendedConnect: 1337}}).Append(nil),
			nil,
			ErrCodeFrameError,
		)
	})
	t.Run("control stream closed before SETTINGS", func(t *testing.T) {
		testConnControlStreamFailures(t, nil, io.EOF, ErrCodeClosedCriticalStream)
	})
	t.Run("control stream reset before SETTINGS", func(t *testing.T) {
		testConnControlStreamFailures(t,
			nil,
			&quic.StreamError{Remote: true, ErrorCode: 42},
			ErrCodeClosedCriticalStream,
		)
	})
}

func TestConnGoAwayFailures(t *testing.T) {
	t.Run("invalid frame", func(t *testing.T) {
		b := (&settingsFrame{}).Append(nil)
		// 1337 is invalid value for the Extended CONNECT setting
		b = (&settingsFrame{Other: map[uint64]uint64{settingExtendedConnect: 1337}}).Append(b)
		testConnControlStreamFailures(t, b, nil, ErrCodeFrameError)
	})
	t.Run("not a GOAWAY", func(t *testing.T) {
		b := (&settingsFrame{}).Append(nil)
		// GOAWAY is the only allowed frame type after SETTINGS
		b = (&headersFrame{}).Append(b)
		testConnControlStreamFailures(t, b, nil, ErrCodeFrameUnexpected)
	})
	t.Run("stream closed before GOAWAY", func(t *testing.T) {
		testConnControlStreamFailures(t, (&settingsFrame{}).Append(nil), io.EOF, ErrCodeClosedCriticalStream)
	})
	t.Run("stream reset before GOAWAY", func(t *testing.T) {
		testConnControlStreamFailures(t,
			(&settingsFrame{}).Append(nil),
			&quic.StreamError{Remote: true, ErrorCode: 42},
			ErrCodeClosedCriticalStream,
		)
	})
	t.Run("invalid stream ID", func(t *testing.T) {
		data := (&settingsFrame{}).Append(nil)
		data = (&goAwayFrame{StreamID: 1}).Append(data)
		testConnControlStreamFailures(t, data, nil, ErrCodeIDError)
	})
	t.Run("increased stream ID", func(t *testing.T) {
		data := (&settingsFrame{}).Append(nil)
		data = (&goAwayFrame{StreamID: 4}).Append(data)
		data = (&goAwayFrame{StreamID: 8}).Append(data)
		testConnControlStreamFailures(t, data, nil, ErrCodeIDError)
	})
}

func testConnControlStreamFailures(t *testing.T, data []byte, readErr error, expectedErr ErrCode) {
	mockCtrl := gomock.NewController(t)
	qconn := mockquic.NewMockEarlyConnection(mockCtrl)
	conn := newConnection(
		context.Background(),
		qconn,
		false,
		protocol.PerspectiveClient,
		nil,
		0,
	)
	b := quicvarint.Append(nil, streamTypeControlStream)
	b = append(b, data...)
	r := bytes.NewReader(b)
	controlStr := mockquic.NewMockStream(mockCtrl)
	controlStr.EXPECT().Read(gomock.Any()).DoAndReturn(func(b []byte) (int, error) {
		if r.Len() == 0 {
			return 0, readErr
		}
		return r.Read(b)
	}).AnyTimes()
	qconn.EXPECT().AcceptUniStream(gomock.Any()).Return(controlStr, nil)
	qconn.EXPECT().AcceptUniStream(gomock.Any()).Return(nil, errors.New("test done"))
	closed := make(chan struct{})

	str := mockquic.NewMockStream(mockCtrl)
	str.EXPECT().StreamID().Return(4).AnyTimes()
	str.EXPECT().Context().Return(context.Background()).AnyTimes()
	qconn.EXPECT().OpenStreamSync(gomock.Any()).Return(str, nil)
	conn.openRequestStream(context.Background(), nil, nil, true, 1000)

	qconn.EXPECT().CloseWithError(quic.ApplicationErrorCode(expectedErr), gomock.Any()).Do(func(quic.ApplicationErrorCode, string) error {
		close(closed)
		return nil
	})
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn.handleUnidirectionalStreams(nil)
	}()
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for close")
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("timeout")
	}
}

func TestConnGoAway(t *testing.T) {
	t.Run("no active streams", func(t *testing.T) {
		testConnGoAway(t, false)
	})
	t.Run("active stream", func(t *testing.T) {
		testConnGoAway(t, true)
	})
}

func testConnGoAway(t *testing.T, withStream bool) {
	mockCtrl := gomock.NewController(t)
	qconn := mockquic.NewMockEarlyConnection(mockCtrl)
	conn := newConnection(
		context.Background(),
		qconn,
		false,
		protocol.PerspectiveClient,
		nil,
		0,
	)
	b := quicvarint.Append(nil, streamTypeControlStream)
	b = (&settingsFrame{}).Append(b)
	b = (&goAwayFrame{StreamID: 8}).Append(b)

	var mockStr *mockquic.MockStream
	var str quic.Stream
	if withStream {
		mockStr = mockquic.NewMockStream(mockCtrl)
		mockStr.EXPECT().StreamID().Return(0).AnyTimes()
		mockStr.EXPECT().Context().Return(context.Background()).AnyTimes()
		qconn.EXPECT().OpenStreamSync(gomock.Any()).Return(mockStr, nil)
		s, err := conn.openRequestStream(context.Background(), nil, nil, true, 1000)
		require.NoError(t, err)
		str = s
	}

	done := make(chan struct{})
	defer close(done)
	r := bytes.NewReader(b)
	controlStr := mockquic.NewMockStream(mockCtrl)
	controlStr.EXPECT().Read(gomock.Any()).DoAndReturn(func(b []byte) (int, error) {
		if r.Len() == 0 {
			<-done
			return 0, errors.New("test done")
		}
		return r.Read(b)
	}).AnyTimes()
	qconn.EXPECT().AcceptUniStream(gomock.Any()).Return(controlStr, nil)
	qconn.EXPECT().AcceptUniStream(gomock.Any()).Return(nil, errors.New("test done"))
	closed := make(chan struct{})
	qconn.EXPECT().CloseWithError(quic.ApplicationErrorCode(ErrCodeNoError), gomock.Any()).Do(func(quic.ApplicationErrorCode, string) error {
		close(closed)
		return nil
	})
	// duplicate calls to CloseWithError are a no-op
	qconn.EXPECT().CloseWithError(gomock.Any(), gomock.Any()).AnyTimes()
	go conn.handleUnidirectionalStreams(nil)

	// the connection should be closed after the stream is closed
	if withStream {
		select {
		case <-closed:
			t.Fatal("connection closed")
		case <-time.After(scaleDuration(10 * time.Millisecond)):
		}

		// The stream ID in the GOAWAY frame is 8, so it's possible to open stream 4.
		mockStr2 := mockquic.NewMockStream(mockCtrl)
		mockStr2.EXPECT().StreamID().Return(4).AnyTimes()
		mockStr2.EXPECT().Context().Return(context.Background()).AnyTimes()
		qconn.EXPECT().OpenStreamSync(gomock.Any()).Return(mockStr2, nil)
		str2, err := conn.openRequestStream(context.Background(), nil, nil, true, 1000)
		require.NoError(t, err)
		mockStr2.EXPECT().Close()
		str2.Close()
		mockStr2.EXPECT().CancelRead(gomock.Any())
		str2.CancelRead(1337)

		// It's not possible to open stream 8.
		_, err = conn.openRequestStream(context.Background(), nil, nil, true, 1000)
		require.ErrorIs(t, err, errGoAway)

		mockStr.EXPECT().Close()
		str.Close()
		mockStr.EXPECT().CancelRead(gomock.Any())
		str.CancelRead(1337)
	}

	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for close")
	}
}

func TestConnRejectPushStream(t *testing.T) {
	t.Run("client", func(t *testing.T) {
		testConnRejectPushStream(t, protocol.PerspectiveClient, ErrCodeStreamCreationError)
	})
	t.Run("server", func(t *testing.T) {
		testConnRejectPushStream(t, protocol.PerspectiveServer, ErrCodeIDError)
	})
}

func testConnRejectPushStream(t *testing.T, pers protocol.Perspective, expectedErr ErrCode) {
	mockCtrl := gomock.NewController(t)
	qconn := mockquic.NewMockEarlyConnection(mockCtrl)
	conn := newConnection(
		context.Background(),
		qconn,
		false,
		pers.Opposite(),
		nil,
		0,
	)
	buf := bytes.NewBuffer(quicvarint.Append(nil, streamTypePushStream))
	controlStr := mockquic.NewMockStream(mockCtrl)
	controlStr.EXPECT().Read(gomock.Any()).DoAndReturn(buf.Read).AnyTimes()
	qconn.EXPECT().AcceptUniStream(gomock.Any()).Return(controlStr, nil)
	qconn.EXPECT().AcceptUniStream(gomock.Any()).Return(nil, errors.New("test done"))
	closed := make(chan struct{})
	qconn.EXPECT().CloseWithError(quic.ApplicationErrorCode(expectedErr), gomock.Any()).Do(func(quic.ApplicationErrorCode, string) error {
		close(closed)
		return nil
	})
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn.handleUnidirectionalStreams(nil)
	}()
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for close")
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("timeout")
	}
}

func TestConnInconsistentDatagramSupport(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	qconn := mockquic.NewMockEarlyConnection(mockCtrl)
	conn := newConnection(
		context.Background(),
		qconn,
		true,
		protocol.PerspectiveClient,
		nil,
		0,
	)
	b := quicvarint.Append(nil, streamTypeControlStream)
	b = (&settingsFrame{Datagram: true}).Append(b)
	controlStr := mockquic.NewMockStream(mockCtrl)
	controlStr.EXPECT().Read(gomock.Any()).DoAndReturn(bytes.NewReader(b).Read).AnyTimes()
	qconn.EXPECT().AcceptUniStream(gomock.Any()).Return(controlStr, nil)
	qconn.EXPECT().AcceptUniStream(gomock.Any()).Return(nil, errors.New("test done"))
	qconn.EXPECT().ConnectionState().Return(quic.ConnectionState{SupportsDatagrams: false})
	closed := make(chan struct{})
	qconn.EXPECT().CloseWithError(quic.ApplicationErrorCode(ErrCodeSettingsError), "missing QUIC Datagram support").Do(func(quic.ApplicationErrorCode, string) error {
		close(closed)
		return nil
	})
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn.handleUnidirectionalStreams(nil)
	}()
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for close")
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("timeout")
	}
}

func TestConnSendAndReceiveDatagram(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	qconn := mockquic.NewMockEarlyConnection(mockCtrl)
	conn := newConnection(
		context.Background(),
		qconn,
		true,
		protocol.PerspectiveClient,
		nil,
		0,
	)
	b := quicvarint.Append(nil, streamTypeControlStream)
	b = (&settingsFrame{Datagram: true}).Append(b)
	r := bytes.NewReader(b)
	done := make(chan struct{})
	defer close(done)
	controlStr := mockquic.NewMockStream(mockCtrl)
	controlStr.EXPECT().Read(gomock.Any()).DoAndReturn(func(b []byte) (int, error) {
		if r.Len() == 0 {
			<-done
		}
		return r.Read(b)
	}).AnyTimes()
	qconn.EXPECT().AcceptUniStream(gomock.Any()).Return(controlStr, nil).MaxTimes(1)
	qconn.EXPECT().AcceptUniStream(gomock.Any()).Return(nil, errors.New("test done")).MaxTimes(1)
	qconn.EXPECT().ConnectionState().Return(quic.ConnectionState{SupportsDatagrams: true}).MaxTimes(1)

	const strID = 4

	// first deliver a datagram...
	// since the stream is not open yet, it will be dropped
	quarterStreamID := quicvarint.Append([]byte{}, strID/4)
	delivered := make(chan struct{})
	qconn.EXPECT().ReceiveDatagram(gomock.Any()).DoAndReturn(func(context.Context) ([]byte, error) {
		close(delivered)
		return append(quarterStreamID, []byte("foo")...), nil
	})
	streamOpened := make(chan struct{})
	qconn.EXPECT().ReceiveDatagram(gomock.Any()).DoAndReturn(func(context.Context) ([]byte, error) {
		<-streamOpened
		return append(quarterStreamID, []byte("bar")...), nil
	}).MaxTimes(1)
	qconn.EXPECT().ReceiveDatagram(gomock.Any()).Return(nil, errors.New("test done")).MaxTimes(1)
	go func() { conn.handleUnidirectionalStreams(nil) }()
	select {
	case <-delivered:
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for datagram delivery")
	}

	// now open the stream...
	qstr := mockquic.NewMockStream(mockCtrl)
	qstr.EXPECT().StreamID().Return(strID).MinTimes(1)
	qstr.EXPECT().Context().Return(context.Background()).AnyTimes()
	qconn.EXPECT().OpenStreamSync(gomock.Any()).Return(qstr, nil)
	str, err := conn.openRequestStream(context.Background(), nil, nil, true, 1000)
	require.NoError(t, err)

	// ... then deliver another datagram
	close(streamOpened)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	data, err := str.ReceiveDatagram(ctx)
	require.NoError(t, err)
	require.Equal(t, []byte("bar"), data)

	// now send a datagram
	const strID2 = 404
	expected := quicvarint.Append([]byte{}, strID2/4)
	expected = append(expected, []byte("foobaz")...)
	qconn.EXPECT().SendDatagram(expected).Return(assert.AnError)
	require.ErrorIs(t, conn.sendDatagram(strID2, []byte("foobaz")), assert.AnError)

	qconn.EXPECT().CloseWithError(gomock.Any(), gomock.Any()).AnyTimes()
}

func TestConnDatagramFailures(t *testing.T) {
	t.Run("invalid varint", func(t *testing.T) {
		testConnDatagramFailures(t, []byte{128})
	})
	t.Run("invalid quarter stream ID", func(t *testing.T) {
		testConnDatagramFailures(t, quicvarint.Append([]byte{}, maxQuarterStreamID+1))
	})
}

func testConnDatagramFailures(t *testing.T, datagram []byte) {
	mockCtrl := gomock.NewController(t)
	qconn := mockquic.NewMockEarlyConnection(mockCtrl)
	conn := newConnection(
		context.Background(),
		qconn,
		true,
		protocol.PerspectiveClient,
		nil,
		0,
	)
	b := quicvarint.Append(nil, streamTypeControlStream)
	b = (&settingsFrame{Datagram: true}).Append(b)
	r := bytes.NewReader(b)
	done := make(chan struct{})
	controlStr := mockquic.NewMockStream(mockCtrl)
	controlStr.EXPECT().Read(gomock.Any()).DoAndReturn(func(b []byte) (int, error) {
		if r.Len() == 0 {
			<-done
		}
		return r.Read(b)
	}).AnyTimes()
	qconn.EXPECT().AcceptUniStream(gomock.Any()).Return(controlStr, nil).MaxTimes(1)
	qconn.EXPECT().AcceptUniStream(gomock.Any()).Return(nil, errors.New("test done")).MaxTimes(1)
	qconn.EXPECT().ConnectionState().Return(quic.ConnectionState{SupportsDatagrams: true}).MaxTimes(1)

	qconn.EXPECT().ReceiveDatagram(gomock.Any()).Return(datagram, nil)
	qconn.EXPECT().CloseWithError(qerr.ApplicationErrorCode(ErrCodeDatagramError), gomock.Any()).Do(func(qerr.ApplicationErrorCode, string) error {
		close(done)
		return nil
	})
	qconn.EXPECT().CloseWithError(gomock.Any(), gomock.Any()).AnyTimes() // further calls to CloseWithError are a no-op
	go func() { conn.handleUnidirectionalStreams(nil) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for close")
	}
}
