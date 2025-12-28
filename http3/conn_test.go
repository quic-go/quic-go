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

	conn := newRawConn(serverConn, false, nil, nil, &eventRecorder, nil)
	b := quicvarint.Append(nil, streamTypeControlStream)
	sf := &settingsFrame{
		MaxFieldSectionSize: 1234,
		Datagram:            true,
		ExtendedConnect:     true,
		Other:               map[uint64]uint64{1337: 42},
	}
	b = sf.Append(b)
	controlStr, err := clientConn.OpenUniStream()
	require.NoError(t, err)
	_, err = controlStr.Write(b)
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	serverStr, err := serverConn.AcceptUniStream(ctx)
	require.NoError(t, err)

	done := make(chan struct{})
	go func() {
		defer close(done)
		conn.handleUnidirectionalStream(serverStr, true)
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

	expectedLen, expectedPayloadLen := expectedFrameLength(t, sf)
	require.Equal(t,
		[]qlogwriter.Event{
			qlog.FrameParsed{
				StreamID: controlStr.StreamID(),
				Raw:      qlog.RawInfo{Length: expectedLen, PayloadLength: expectedPayloadLen},
				Frame: qlog.Frame{
					Frame: qlog.SettingsFrame{
						MaxFieldSectionSize: 1234,
						Datagram:            pointer(true),
						ExtendedConnect:     pointer(true),
						Other:               map[uint64]uint64{1337: 42},
					},
				},
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

	conn := newRawConn(serverConn, false, nil, nil, nil, nil)
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

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	serverStr1, err := serverConn.AcceptUniStream(ctx)
	require.NoError(t, err)
	serverStr2, err := serverConn.AcceptUniStream(ctx)
	require.NoError(t, err)

	done := make(chan struct{}, 2)
	go func() {
		defer func() { done <- struct{}{} }()
		conn.handleUnidirectionalStream(serverStr1, true)
	}()
	go func() {
		defer func() { done <- struct{}{} }()
		conn.handleUnidirectionalStream(serverStr2, true)
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
	for range 2 {
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatal("timeout")
		}
	}
}

func TestConnResetUnknownUniStream(t *testing.T) {
	clientConn, serverConn := newConnPair(t)

	conn := newRawConn(serverConn, false, nil, nil, nil, nil)
	buf := bytes.NewBuffer(quicvarint.Append(nil, 0x1337))
	str, err := clientConn.OpenUniStream()
	require.NoError(t, err)
	_, err = str.Write(buf.Bytes())
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	serverStr, err := serverConn.AcceptUniStream(ctx)
	require.NoError(t, err)

	done := make(chan struct{})
	go func() {
		defer close(done)
		conn.handleUnidirectionalStream(serverStr, true)
	}()
	expectStreamWriteReset(t, str, quic.StreamErrorCode(ErrCodeStreamCreationError))
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

func testConnControlStreamFailures(t *testing.T, data []byte, readErr error, expectedErr ErrCode) {
	clientConn, serverConn := newConnPair(t)

	conn := newRawConn(clientConn, false, nil, nil, nil, nil)
	controlStr, err := serverConn.OpenUniStream()
	require.NoError(t, err)
	_, err = controlStr.Write(quicvarint.Append(nil, streamTypeControlStream))
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	clientStr, err := clientConn.AcceptUniStream(ctx)
	require.NoError(t, err)

	done := make(chan struct{})
	go func() {
		defer close(done)
		conn.handleUnidirectionalStream(clientStr, false)
	}()

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

func TestConnControlStreamHandler(t *testing.T) {
	t.Run("with handler", func(t *testing.T) { testConnControlStreamHandler(t, true) })
	t.Run("without handler", func(t *testing.T) { testConnControlStreamHandler(t, false) })
}

func testConnControlStreamHandler(t *testing.T, useHandler bool) {
	localConn, peerConn := newConnPair(t)

	handlerCalled := make(chan struct{})
	var controlStrHandler func(*quic.ReceiveStream, *frameParser)
	if useHandler {
		controlStrHandler = func(*quic.ReceiveStream, *frameParser) { close(handlerCalled) }
	}
	conn := newRawConn(localConn, false, nil, controlStrHandler, nil, nil)

	b := quicvarint.Append(nil, streamTypeControlStream)
	b = (&settingsFrame{}).Append(b)
	str, err := peerConn.OpenUniStream()
	require.NoError(t, err)
	_, err = str.Write(b)
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	localStr, err := localConn.AcceptUniStream(ctx)
	require.NoError(t, err)

	done := make(chan struct{})
	go func() {
		defer close(done)
		conn.handleUnidirectionalStream(localStr, false)
	}()

	select {
	case <-conn.ReceivedSettings():
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for settings")
	}
	if useHandler {
		select {
		case <-handlerCalled:
		case <-time.After(time.Second):
			t.Fatal("timeout waiting for handler to be called")
		}
	} else {
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatal("timeout waiting for handler to return")
		}
	}
}

func TestConnRejectPushStream(t *testing.T) {
	t.Run("client", func(t *testing.T) {
		testConnRejectPushStream(t, false, ErrCodeIDError)
	})
	t.Run("server", func(t *testing.T) {
		testConnRejectPushStream(t, true, ErrCodeStreamCreationError)
	})
}

func testConnRejectPushStream(t *testing.T, isServer bool, expectedErr ErrCode) {
	localConn, peerConn := newConnPair(t)

	conn := newRawConn(localConn, false, nil, nil, nil, nil)
	buf := bytes.NewBuffer(quicvarint.Append(nil, streamTypePushStream))
	str, err := peerConn.OpenUniStream()
	require.NoError(t, err)
	_, err = str.Write(buf.Bytes())
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	localStr, err := localConn.AcceptUniStream(ctx)
	require.NoError(t, err)

	done := make(chan struct{})
	go func() {
		defer close(done)
		conn.handleUnidirectionalStream(localStr, isServer)
	}()
	select {
	case <-peerConn.Context().Done():
		require.ErrorIs(t,
			context.Cause(peerConn.Context()),
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

	conn := newRawConn(clientConn, true, nil, nil, nil, nil)
	b := quicvarint.Append(nil, streamTypeControlStream)
	b = (&settingsFrame{Datagram: true}).Append(b)
	controlStr, err := serverConn.OpenUniStream()
	require.NoError(t, err)
	_, err = controlStr.Write(b)
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	clientStr, err := clientConn.AcceptUniStream(ctx)
	require.NoError(t, err)

	done := make(chan struct{})
	go func() {
		defer close(done)
		conn.handleUnidirectionalStream(clientStr, false)
	}()

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

	conn := newRawConn(clientConn, true, nil, nil, &eventRecorder, nil)
	b := quicvarint.Append(nil, streamTypeControlStream)
	b = (&settingsFrame{Datagram: true}).Append(b)
	controlStr, err := serverConn.OpenUniStream()
	require.NoError(t, err)
	_, err = controlStr.Write(b)
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	clientStr, err := clientConn.AcceptUniStream(ctx)
	require.NoError(t, err)

	done := make(chan struct{})
	go func() {
		defer close(done)
		conn.handleUnidirectionalStream(clientStr, false)
	}()

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
	str0, err := clientConn.OpenStreamSync(context.Background())
	require.NoError(t, err)
	str0.Close()

	str, err := clientConn.OpenStream()
	require.NoError(t, err)
	require.Equal(t, quic.StreamID(strID), str.StreamID())
	datagramStr := conn.TrackStream(str)

	// now open the stream...
	require.NoError(t, serverConn.SendDatagram(append(quarterStreamID, []byte("bar")...)))

	data, err := datagramStr.ReceiveDatagram(ctx)
	require.NoError(t, err)
	require.Equal(t, []byte("bar"), data)

	// now send a datagram
	require.NoError(t, datagramStr.SendDatagram([]byte("foobaz")))

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
	localConn, peerConn := newConnPairWithDatagrams(t, nil, nil)

	conn := newRawConn(localConn, true, nil, nil, nil, nil)

	b := quicvarint.Append(nil, streamTypeControlStream)
	b = (&settingsFrame{Datagram: true}).Append(b)
	controlStr, err := peerConn.OpenUniStream()
	require.NoError(t, err)
	_, err = controlStr.Write(b)
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	localStr, err := localConn.AcceptUniStream(ctx)
	require.NoError(t, err)

	go conn.handleUnidirectionalStream(localStr, false)

	// Wait for SETTINGS to be received and datagram handling to start
	select {
	case <-conn.ReceivedSettings():
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for settings")
	}

	require.NoError(t, peerConn.SendDatagram(datagram))

	select {
	case <-peerConn.Context().Done():
		require.ErrorIs(t,
			context.Cause(peerConn.Context()),
			&quic.ApplicationError{Remote: true, ErrorCode: quic.ApplicationErrorCode(ErrCodeDatagramError)},
		)
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for close")
	}
}
