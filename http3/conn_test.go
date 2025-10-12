package http3

import (
	"bytes"
	"context"
	"io"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3/qlog"
	"github.com/quic-go/quic-go/qlogwriter"
	"github.com/quic-go/quic-go/quicvarint"
	"github.com/quic-go/quic-go/testutils/events"

	"github.com/stretchr/testify/require"
)

func TestConnReceiveSettings(t *testing.T) {
	var eventRecorder events.Recorder
	clientConn, serverConn := newConnPairWithRecorder(t, nil, &eventRecorder)

	conn := newConnection(
		serverConn.Context(),
		serverConn,
		false,
		true, // server
		nil,
		0,
	)
	b := quicvarint.Append(nil, streamTypeControlStream)
	b = (&settingsFrame{
		Datagram:        true,
		ExtendedConnect: true,
		Other:           map[uint64]uint64{1337: 42},
	}).Append(b)
	controlStr, err := clientConn.OpenUniStream()
	require.NoError(t, err)
	_, err = controlStr.Write(b)
	require.NoError(t, err)

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

	require.Equal(t,
		[]qlogwriter.Event{
			qlog.FrameParsed{
				StreamID: controlStr.StreamID(),
				Raw:      qlog.RawInfo{PayloadLength: len(b) - 3}, // type and length
				Frame:    qlog.Frame{Frame: qlog.SettingsFrame{Datagram: pointer(true), ExtendedConnect: pointer(true), Other: map[uint64]uint64{1337: 42}}},
			},
		},
		filterQlogEventsForFrame(eventRecorder.Events(qlog.FrameParsed{}), qlog.SettingsFrame{}),
	)
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
	clientConn, serverConn := newConnPair(t)

	conn := newConnection(
		context.Background(),
		serverConn,
		false,
		true, // server
		nil,
		0,
	)
	b := quicvarint.Append(nil, typ)
	if typ == streamTypeControlStream {
		b = (&settingsFrame{}).Append(b)
	}
	controlStr1, err := clientConn.OpenUniStream()
	require.NoError(t, err)
	_, err = controlStr1.Write(b)
	require.NoError(t, err)
	controlStr2, err := clientConn.OpenUniStream()
	require.NoError(t, err)
	_, err = controlStr2.Write(b)
	require.NoError(t, err)

	done := make(chan struct{})
	go func() {
		defer close(done)
		conn.handleUnidirectionalStreams(nil)
	}()
	select {
	case <-clientConn.Context().Done():
		require.ErrorIs(t,
			context.Cause(clientConn.Context()),
			&quic.ApplicationError{Remote: true, ErrorCode: quic.ApplicationErrorCode(ErrCodeStreamCreationError)},
		)
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
	clientConn, serverConn := newConnPair(t)

	conn := newConnection(
		context.Background(),
		serverConn,
		false,
		true, // server
		nil,
		0,
	)
	buf := bytes.NewBuffer(quicvarint.Append(nil, 0x1337))
	str, err := clientConn.OpenUniStream()
	require.NoError(t, err)
	_, err = str.Write(buf.Bytes())
	require.NoError(t, err)

	go conn.handleUnidirectionalStreams(nil)

	expectStreamWriteReset(t, str, quic.StreamErrorCode(ErrCodeStreamCreationError))
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
	clientConn, serverConn := newConnPair(t)

	conn := newConnection(
		clientConn.Context(),
		clientConn,
		false,
		false, // client
		nil,
		0,
	)
	controlStr, err := serverConn.OpenUniStream()
	require.NoError(t, err)
	_, err = controlStr.Write(quicvarint.Append(nil, streamTypeControlStream))
	require.NoError(t, err)

	done := make(chan struct{})
	go func() {
		defer close(done)
		conn.handleUnidirectionalStreams(nil)
	}()

	conn.openRequestStream(context.Background(), nil, nil, true, 1000)

	switch readErr {
	case nil:
		_, err = controlStr.Write(data)
		require.NoError(t, err)
	case io.EOF:
		_, err = controlStr.Write(data)
		require.NoError(t, err)
		require.NoError(t, controlStr.Close())
	default:
		// make sure the stream type is received
		time.Sleep(scaleDuration(10 * time.Millisecond))
		controlStr.CancelWrite(1337)
	}

	select {
	case <-serverConn.Context().Done():
		require.ErrorIs(t,
			context.Cause(serverConn.Context()),
			&quic.ApplicationError{Remote: true, ErrorCode: quic.ApplicationErrorCode(expectedErr)},
		)
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
	var clientEventRecorder events.Recorder
	clientConn, serverConn := newConnPairWithRecorder(t, &clientEventRecorder, nil)

	conn := newConnection(
		clientConn.Context(),
		clientConn,
		false,
		false, // client
		nil,
		0,
	)
	b := quicvarint.Append(nil, streamTypeControlStream)
	b = (&settingsFrame{}).Append(b)
	b = (&goAwayFrame{StreamID: 8}).Append(b)

	var str *RequestStream
	if withStream {
		s, err := conn.openRequestStream(context.Background(), nil, nil, true, 1000)
		require.NoError(t, err)
		str = s
	}

	controlStr, err := serverConn.OpenUniStream()
	require.NoError(t, err)
	_, err = controlStr.Write(b)
	require.NoError(t, err)

	go conn.handleUnidirectionalStreams(nil)

	// the connection should be closed after the stream is closed
	if withStream {
		select {
		case <-serverConn.Context().Done():
			t.Fatal("connection closed")
		case <-time.After(scaleDuration(10 * time.Millisecond)):
		}

		// The stream ID in the GOAWAY frame is 8, so it's possible to open stream 4.
		str2, err := conn.openRequestStream(context.Background(), nil, nil, true, 1000)
		require.NoError(t, err)
		str2.Close()
		str2.CancelRead(1337)

		// It's not possible to open stream 8.
		_, err = conn.openRequestStream(context.Background(), nil, nil, true, 1000)
		require.ErrorIs(t, err, errGoAway)

		str.Close()
		str.CancelRead(1337)
	}

	select {
	case <-serverConn.Context().Done():
		require.ErrorIs(t,
			context.Cause(serverConn.Context()),
			&quic.ApplicationError{Remote: true, ErrorCode: quic.ApplicationErrorCode(ErrCodeNoError)},
		)
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for close")
	}

	require.Equal(t,
		[]qlogwriter.Event{
			qlog.FrameParsed{
				StreamID: 3,
				Frame:    qlog.Frame{Frame: qlog.GoAwayFrame{StreamID: 8}},
			},
		},
		filterQlogEventsForFrame(clientEventRecorder.Events(qlog.FrameParsed{}), qlog.GoAwayFrame{StreamID: 8}),
	)
}

func TestConnRejectPushStream(t *testing.T) {
	t.Run("client", func(t *testing.T) {
		testConnRejectPushStream(t, false, ErrCodeStreamCreationError)
	})
	t.Run("server", func(t *testing.T) {
		testConnRejectPushStream(t, true, ErrCodeIDError)
	})
}

func testConnRejectPushStream(t *testing.T, isServer bool, expectedErr ErrCode) {
	clientConn, serverConn := newConnPair(t)

	conn := newConnection(
		clientConn.Context(),
		clientConn,
		false,
		!isServer,
		nil,
		0,
	)
	buf := bytes.NewBuffer(quicvarint.Append(nil, streamTypePushStream))
	controlStr, err := serverConn.OpenUniStream()
	require.NoError(t, err)
	_, err = controlStr.Write(buf.Bytes())
	require.NoError(t, err)

	done := make(chan struct{})
	go func() {
		defer close(done)
		conn.handleUnidirectionalStreams(nil)
	}()
	select {
	case <-serverConn.Context().Done():
		require.ErrorIs(t,
			context.Cause(serverConn.Context()),
			&quic.ApplicationError{Remote: true, ErrorCode: quic.ApplicationErrorCode(expectedErr)},
		)
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
	clientConn, serverConn := newConnPair(t)

	conn := newConnection(
		clientConn.Context(),
		clientConn,
		true,
		false, // client
		nil,
		0,
	)
	b := quicvarint.Append(nil, streamTypeControlStream)
	b = (&settingsFrame{Datagram: true}).Append(b)
	controlStr, err := serverConn.OpenUniStream()
	require.NoError(t, err)
	_, err = controlStr.Write(b)
	require.NoError(t, err)

	go conn.handleUnidirectionalStreams(nil)

	select {
	case <-serverConn.Context().Done():
		err := context.Cause(serverConn.Context())
		require.ErrorIs(t, err, &quic.ApplicationError{Remote: true, ErrorCode: quic.ApplicationErrorCode(ErrCodeSettingsError)})
		require.ErrorContains(t, err, "missing QUIC Datagram support")
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for close")
	}
}

func TestConnSendAndReceiveDatagram(t *testing.T) {
	var eventRecorder events.Recorder
	clientConn, serverConn := newConnPairWithDatagrams(t, &eventRecorder, nil)

	conn := newConnection(
		clientConn.Context(),
		clientConn,
		true,
		false, // client
		nil,
		0,
	)
	b := quicvarint.Append(nil, streamTypeControlStream)
	b = (&settingsFrame{Datagram: true}).Append(b)
	controlStr, err := serverConn.OpenUniStream()
	require.NoError(t, err)
	_, err = controlStr.Write(b)
	require.NoError(t, err)

	go conn.handleUnidirectionalStreams(nil)

	const strID = 4

	// first deliver a datagram...
	// since the stream is not open yet, it will be dropped
	quarterStreamID := quicvarint.Append([]byte{}, strID/4)

	datagram := append(quarterStreamID, []byte("foo")...)
	require.NoError(t, serverConn.SendDatagram(datagram))
	time.Sleep(scaleDuration(10 * time.Millisecond)) // give the datagram a chance to be delivered

	require.Equal(t,
		[]qlogwriter.Event{
			qlog.DatagramParsed{
				QuaterStreamID: strID / 4,
				Raw:            qlog.RawInfo{Length: len(datagram), PayloadLength: 3},
			},
		},
		eventRecorder.Events(qlog.DatagramParsed{}),
	)
	eventRecorder.Clear()

	// don't use stream 0, since that makes it hard to test that the quarter stream ID is used
	str1, err := conn.openRequestStream(context.Background(), nil, nil, true, 1000)
	require.NoError(t, err)
	str1.Close()

	str, err := conn.openRequestStream(context.Background(), nil, nil, true, 1000)
	require.NoError(t, err)
	require.Equal(t, quic.StreamID(strID), str.StreamID())

	// now open the stream...
	require.NoError(t, serverConn.SendDatagram(append(quarterStreamID, []byte("bar")...)))

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	data, err := str.ReceiveDatagram(ctx)
	require.NoError(t, err)
	require.Equal(t, []byte("bar"), data)

	// now send a datagram
	str.SendDatagram([]byte("foobaz"))

	expected := quicvarint.Append([]byte{}, strID/4)
	expected = append(expected, []byte("foobaz")...)

	require.Equal(t,
		[]qlogwriter.Event{
			qlog.DatagramCreated{
				QuaterStreamID: strID / 4,
				Raw:            qlog.RawInfo{PayloadLength: 6, Length: len(expected)},
			},
		},
		eventRecorder.Events(qlog.DatagramCreated{}),
	)
	eventRecorder.Clear()

	data, err = serverConn.ReceiveDatagram(ctx)
	require.NoError(t, err)
	require.Equal(t, expected, data)
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
	clientConn, serverConn := newConnPairWithDatagrams(t, nil, nil)

	conn := newConnection(
		clientConn.Context(),
		clientConn,
		true,
		false, // client
		nil,
		0,
	)
	b := quicvarint.Append(nil, streamTypeControlStream)
	b = (&settingsFrame{Datagram: true}).Append(b)
	controlStr, err := serverConn.OpenUniStream()
	require.NoError(t, err)
	_, err = controlStr.Write(b)
	require.NoError(t, err)

	require.NoError(t, serverConn.SendDatagram(datagram))

	go func() { conn.handleUnidirectionalStreams(nil) }()
	select {
	case <-serverConn.Context().Done():
		require.ErrorIs(t,
			context.Cause(serverConn.Context()),
			&quic.ApplicationError{Remote: true, ErrorCode: quic.ApplicationErrorCode(ErrCodeDatagramError)},
		)
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for close")
	}
}
