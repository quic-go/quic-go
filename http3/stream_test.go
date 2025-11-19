package http3

import (
	"bytes"
	"context"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"strings"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3/qlog"
	"github.com/quic-go/quic-go/qlogwriter"
	"github.com/quic-go/quic-go/testutils/events"

	"github.com/quic-go/qpack"

	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

func getDataFrame(data []byte) []byte {
	b := (&dataFrame{Length: uint64(len(data))}).Append(nil)
	return append(b, data...)
}

func TestStreamReadDataFrames(t *testing.T) {
	var buf bytes.Buffer
	mockCtrl := gomock.NewController(t)
	qstr := NewMockDatagramStream(mockCtrl)
	qstr.EXPECT().StreamID().Return(quic.StreamID(42)).AnyTimes()
	qstr.EXPECT().Write(gomock.Any()).DoAndReturn(buf.Write).AnyTimes()
	qstr.EXPECT().Read(gomock.Any()).DoAndReturn(buf.Read).AnyTimes()

	var eventRecorder events.Recorder
	clientConn, _ := newConnPairWithRecorder(t, &eventRecorder, nil)
	str := newStream(
		qstr,
		newConnection(
			clientConn.Context(),
			clientConn,
			false,
			false, // client
			nil,
			0,
		),
		nil,
		func(io.Reader, *headersFrame) error { return nil },
		&eventRecorder,
	)

	buf.Write(getDataFrame([]byte("foobar")))
	b := make([]byte, 3)
	n, err := str.Read(b)
	require.NoError(t, err)
	require.Equal(t, 3, n)
	require.Equal(t, []byte("foo"), b)
	n, err = str.Read(b)
	require.NoError(t, err)
	require.Equal(t, 3, n)
	require.Equal(t, []byte("bar"), b)

	expectedLen, _ := expectedFrameLength(t, &dataFrame{Length: 6})
	require.Equal(t,
		[]qlogwriter.Event{
			qlog.FrameParsed{
				StreamID: 42,
				Raw:      qlog.RawInfo{Length: expectedLen, PayloadLength: 6},
				Frame:    qlog.Frame{Frame: qlog.DataFrame{}},
			},
		},
		eventRecorder.Events(qlog.FrameParsed{}),
	)
	eventRecorder.Clear()

	buf.Write(getDataFrame([]byte("baz")))
	b = make([]byte, 10)
	n, err = str.Read(b)
	require.NoError(t, err)
	require.Equal(t, 3, n)
	require.Equal(t, []byte("baz"), b[:n])
	require.Len(t, eventRecorder.Events(qlog.FrameParsed{}), 1)
	eventRecorder.Clear()

	buf.Write(getDataFrame([]byte("lorem")))
	buf.Write(getDataFrame([]byte("ipsum")))

	data, err := io.ReadAll(str)
	require.NoError(t, err)
	require.Equal(t, "loremipsum", string(data))
	require.Len(t, eventRecorder.Events(qlog.FrameParsed{}), 2)
	eventRecorder.Clear()

	// invalid frame
	buf.Write([]byte("invalid"))
	_, err = str.Read([]byte{0})
	require.Error(t, err)
}

func TestStreamInvalidFrame(t *testing.T) {
	var buf bytes.Buffer
	b := (&settingsFrame{}).Append(nil)
	buf.Write(b)

	mockCtrl := gomock.NewController(t)
	qstr := NewMockDatagramStream(mockCtrl)
	qstr.EXPECT().StreamID().Return(quic.StreamID(42)).AnyTimes()
	qstr.EXPECT().Write(gomock.Any()).DoAndReturn(buf.Write).AnyTimes()
	qstr.EXPECT().Read(gomock.Any()).DoAndReturn(buf.Read).AnyTimes()
	clientConn, serverConn := newConnPair(t)

	str := newStream(
		qstr,
		newConnection(context.Background(), clientConn, false, false, nil, 0),
		nil,
		func(io.Reader, *headersFrame) error { return nil },
		nil,
	)

	_, err := str.Read([]byte{0})
	require.ErrorContains(t, err, "peer sent an unexpected frame")

	select {
	case <-serverConn.Context().Done():
		var appErr *quic.ApplicationError
		require.ErrorAs(t, context.Cause(serverConn.Context()), &appErr)
		require.Equal(t, quic.ApplicationErrorCode(ErrCodeFrameUnexpected), appErr.ErrorCode)
	case <-time.After(time.Second):
		t.Fatal("timeout")
	}
}

func TestStreamWrite(t *testing.T) {
	var buf bytes.Buffer
	mockCtrl := gomock.NewController(t)
	qstr := NewMockDatagramStream(mockCtrl)
	qstr.EXPECT().StreamID().Return(quic.StreamID(42)).AnyTimes()
	qstr.EXPECT().Write(gomock.Any()).DoAndReturn(buf.Write).AnyTimes()
	var eventRecorder events.Recorder
	str := newStream(qstr, nil, nil, func(io.Reader, *headersFrame) error { return nil }, &eventRecorder)
	str.Write([]byte("foo"))
	str.Write([]byte("foobar"))

	fp := frameParser{r: &buf}
	f, err := fp.ParseNext(nil)
	require.NoError(t, err)
	f1Len, f1PayloadLen := expectedFrameLength(t, &dataFrame{Length: 3})
	require.Equal(t, &dataFrame{Length: 3}, f)
	b := make([]byte, 3)
	_, err = io.ReadFull(&buf, b)
	require.NoError(t, err)
	require.Equal(t, []byte("foo"), b)

	fp = frameParser{r: &buf}
	f, err = fp.ParseNext(nil)
	require.NoError(t, err)
	f2Len, f2PayloadLen := expectedFrameLength(t, &dataFrame{Length: 6})
	require.Equal(t, &dataFrame{Length: 6}, f)
	b = make([]byte, 6)
	_, err = io.ReadFull(&buf, b)
	require.NoError(t, err)
	require.Equal(t, []byte("foobar"), b)

	require.Equal(t,
		[]qlogwriter.Event{
			qlog.FrameCreated{
				StreamID: 42,
				Raw:      qlog.RawInfo{Length: f1Len, PayloadLength: f1PayloadLen},
				Frame:    qlog.Frame{Frame: qlog.DataFrame{}},
			},
			qlog.FrameCreated{
				StreamID: 42,
				Raw:      qlog.RawInfo{Length: f2Len, PayloadLength: f2PayloadLen},
				Frame:    qlog.Frame{Frame: qlog.DataFrame{}},
			},
		},
		eventRecorder.Events(qlog.FrameCreated{}),
	)
}

func TestRequestStream(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	qstr := NewMockDatagramStream(mockCtrl)
	qstr.EXPECT().StreamID().Return(quic.StreamID(42)).AnyTimes()
	requestWriter := newRequestWriter()
	clientConn, _ := newConnPair(t)
	str := newRequestStream(
		newStream(
			qstr,
			newConnection(context.Background(), clientConn, false, false, nil, 0),
			&httptrace.ClientTrace{},
			func(io.Reader, *headersFrame) error { return nil },
			nil,
		),
		requestWriter,
		make(chan struct{}),
		qpack.NewDecoder(),
		true,
		math.MaxInt,
		&http.Response{},
	)

	_, err := str.Read([]byte{0})
	require.EqualError(t, err, "http3: invalid use of RequestStream.Read before ReadResponse")
	_, err = str.Write([]byte{0})
	require.EqualError(t, err, "http3: invalid use of RequestStream.Write before SendRequestHeader")

	// calling ReadResponse before SendRequestHeader is not valid
	_, err = str.ReadResponse()
	require.EqualError(t, err, "http3: invalid duplicate use of RequestStream.ReadResponse before SendRequestHeader")
	// SendRequestHeader can't be used for requests that have a request body
	require.EqualError(t,
		str.SendRequestHeader(
			httptest.NewRequest(http.MethodGet, "https://quic-go.net", strings.NewReader("foobar")),
		),
		"http3: invalid use of RequestStream.SendRequestHeader with a request that has a request body",
	)

	req := httptest.NewRequest(http.MethodGet, "https://quic-go.net", nil)
	qstr.EXPECT().Write(gomock.Any()).AnyTimes()
	require.NoError(t, str.SendRequestHeader(req))
	// duplicate calls are not allowed
	require.EqualError(t, str.SendRequestHeader(req), "http3: invalid duplicate use of RequestStream.SendRequestHeader")

	buf := bytes.NewBuffer(encodeResponse(t, 200))
	buf.Write((&dataFrame{Length: 6}).Append(nil))
	buf.Write([]byte("foobar"))
	qstr.EXPECT().Read(gomock.Any()).DoAndReturn(buf.Read).AnyTimes()
	rsp, err := str.ReadResponse()
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, rsp.StatusCode)

	b := make([]byte, 10)
	n, err := str.Read(b)
	require.NoError(t, err)
	require.Equal(t, 6, n)
	require.Equal(t, []byte("foobar"), b[:n])
}

func TestRequestStreamUsesQPACKErrorCode(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	decoder := qpack.NewDecoder()

	// Create a valid HEADERS frame with intentionally corrupted QPACK data
	// This will cause QPACK decoding to fail
	hf := &headersFrame{Length: 100}
	hfBytes := hf.Append(nil)
	corruptedQPACKData := bytes.Repeat([]byte{0xff}, 100) // Invalid QPACK data
	headerData := append(hfBytes, corruptedQPACKData...)

	buf := bytes.NewBuffer(headerData)

	str := NewMockDatagramStream(mockCtrl)
	str.EXPECT().StreamID().Return(quic.StreamID(42)).AnyTimes()
	str.EXPECT().Read(gomock.Any()).DoAndReturn(buf.Read).AnyTimes()
	str.EXPECT().Context().Return(context.Background()).AnyTimes()
	// Expect CancelRead and CancelWrite to be called with QPACK error code
	str.EXPECT().CancelRead(quic.StreamErrorCode(ErrCodeQPACKDecompressionFailed))
	str.EXPECT().CancelWrite(quic.StreamErrorCode(ErrCodeQPACKDecompressionFailed))

	reqStream := newRequestStream(
		newStream(str, &Conn{decoder: decoder, isServer: false}, nil, nil, nil),
		nil,
		nil,
		decoder,
		false,
		10000,
		&http.Response{},
	)
	reqStream.sentRequest = true

	_, err := reqStream.ReadResponse()
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid response")
}
