package http3

import (
	"bytes"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strconv"
	"testing"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3/qlog"
	"github.com/quic-go/quic-go/testutils/events"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

type testResponseWriter struct {
	*responseWriter
	eventRecorder *events.Recorder
	buf           *bytes.Buffer
}

func (rw *testResponseWriter) DecodeHeaders(t *testing.T, idx int) map[string][]string {
	t.Helper()

	rw.Flush()
	rw.flushTrailers()
	startLen := rw.buf.Len()
	frame, err := (&frameParser{r: rw.buf}).ParseNext(nil)
	require.NoError(t, err)
	require.IsType(t, &headersFrame{}, frame)
	payloadLen := frame.(*headersFrame).Length
	data := make([]byte, payloadLen)
	headerFrameLen := startLen - rw.buf.Len() + len(data)
	_, err = io.ReadFull(rw.buf, data)
	require.NoError(t, err)
	hfs := decodeQpackHeaderFields(t, data)

	// check that the decoded header fields are properly logged
	require.GreaterOrEqual(t, len(rw.eventRecorder.Events(qlog.FrameCreated{})), idx+1)
	require.IsType(t, qlog.HeadersFrame{}, rw.eventRecorder.Events()[idx].(qlog.FrameCreated).Frame.Frame)
	ev := rw.eventRecorder.Events()[idx].(qlog.FrameCreated)
	assert.Equal(t, quic.StreamID(42), ev.StreamID)
	assert.Equal(t, headerFrameLen, ev.Raw.Length, "raw.Length")
	assert.Equal(t, int(payloadLen), ev.Raw.PayloadLength, "raw.PayloadLength")

	fields := make(map[string][]string)
	for _, p := range hfs {
		fields[p.Name] = append(fields[p.Name], p.Value)
		require.Contains(t,
			ev.Frame.Frame.(qlog.HeadersFrame).HeaderFields,
			qlog.HeaderField{Name: p.Name, Value: p.Value},
		)
	}

	return fields
}

func (rw *testResponseWriter) DecodeBody(t *testing.T) []byte {
	t.Helper()

	frame, err := (&frameParser{r: rw.buf}).ParseNext(nil)
	if err == io.EOF {
		return nil
	}
	require.NoError(t, err)
	require.IsType(t, &dataFrame{}, frame)
	body := make([]byte, frame.(*dataFrame).Length)
	_, err = io.ReadFull(rw.buf, body)
	require.NoError(t, err)
	return body
}

func newTestResponseWriter(t *testing.T) *testResponseWriter {
	var eventRecorder events.Recorder
	buf := &bytes.Buffer{}
	mockCtrl := gomock.NewController(t)
	str := NewMockDatagramStream(mockCtrl)
	str.EXPECT().StreamID().Return(quic.StreamID(42)).AnyTimes()
	str.EXPECT().Write(gomock.Any()).DoAndReturn(buf.Write).AnyTimes()
	str.EXPECT().SetReadDeadline(gomock.Any()).Return(nil).AnyTimes()
	str.EXPECT().SetWriteDeadline(gomock.Any()).Return(nil).AnyTimes()
	clientConn, _ := newConnPair(t)
	conn := newRawConn(clientConn, false, nil, nopControlStrHandler, &eventRecorder, nil)
	rw := newResponseWriter(
		newServerStream(str, conn, func(io.Reader, *headersFrame) error { return nil }, &eventRecorder),
		nil,
		http.MethodGet,
		slog.Default(),
	)
	return &testResponseWriter{
		responseWriter: rw,
		eventRecorder:  &eventRecorder,
		buf:            buf,
	}
}

func TestResponseWriterInvalidStatus(t *testing.T) {
	rw := newTestResponseWriter(t)
	require.PanicsWithValue(t, "invalid WriteHeader code 99", func() { rw.WriteHeader(99) })
	require.PanicsWithValue(t, "invalid WriteHeader code 1000", func() { rw.WriteHeader(1000) })
}

func TestResponseWriterHeader(t *testing.T) {
	rw := newTestResponseWriter(t)
	rw.Header().Add("Content-Length", "42")
	rw.Header().Set("Priority", "u=0")
	rw.WriteHeader(http.StatusTeapot) // 418
	// repeated WriteHeader calls are ignored
	rw.WriteHeader(http.StatusInternalServerError)

	// set cookies
	http.SetCookie(rw, &http.Cookie{Name: "foo", Value: "bar"})
	http.SetCookie(rw, &http.Cookie{Name: "baz", Value: "lorem ipsum"})
	// write some data
	rw.Write([]byte("foobar"))

	fields := rw.DecodeHeaders(t, 0)
	require.Equal(t, []string{"418"}, fields[":status"])
	require.Equal(t, []string{"42"}, fields["content-length"])
	require.Equal(t, []string{"u=0"}, fields["priority"])
	require.Equal(t,
		[]string{"foo=bar", `baz="lorem ipsum"`},
		fields["set-cookie"],
	)
	require.Equal(t, []byte("foobar"), rw.DecodeBody(t))
}

func TestResponseWriterConnectionSpecificHeaders(t *testing.T) {
	rw := newTestResponseWriter(t)
	for _, name := range []string{"Connection", "Keep-Alive", "Proxy-Connection", "Transfer-Encoding", "Upgrade"} {
		rw.Header().Set(name, "foo")
	}
	rw.Header().Set("Te", "trailers") // TE is only allowed in request headers
	rw.Header().Set("Invalid", "foo\r\nbar")
	rw.Header().Set("Date", "today")
	rw.WriteHeader(http.StatusOK)

	require.Equal(t, map[string][]string{":status": {"200"}, "date": {"today"}}, rw.DecodeHeaders(t, 0))
}

func TestResponseWriterDataWithoutHeader(t *testing.T) {
	rw := newTestResponseWriter(t)
	rw.Write([]byte("foobar"))

	fields := rw.DecodeHeaders(t, 0)
	require.Equal(t, []string{"200"}, fields[":status"])
	require.Equal(t, []byte("foobar"), rw.DecodeBody(t))
}

func TestResponseWriterDataStatusWithoutBody(t *testing.T) {
	rw := newTestResponseWriter(t)
	rw.WriteHeader(http.StatusNotModified)
	n, err := rw.Write([]byte("foobar"))
	require.Zero(t, n)
	require.ErrorIs(t, err, http.ErrBodyNotAllowed)
	require.NoError(t, rw.Finish())

	fields := rw.DecodeHeaders(t, 0)
	require.Equal(t, []string{"304"}, fields[":status"])
	require.NotContains(t, fields, "content-length")
	require.Empty(t, rw.DecodeBody(t))
}

func TestResponseWriterHTTPStream(t *testing.T) {
	t.Run("with WriteHeader", func(t *testing.T) {
		rw := newTestResponseWriter(t)
		rw.Header().Set("Capsule-Protocol", "?1")
		rw.WriteHeader(http.StatusOK)
		require.NoError(t, rw.FlushError())
		str := rw.HTTPStream()
		_, err := str.Write([]byte("foobar"))
		require.NoError(t, err)
		n, err := rw.Write([]byte("raboof"))
		require.ErrorIs(t, err, http.ErrHijacked)
		require.Zero(t, n)

		fields := rw.DecodeHeaders(t, 0)
		require.Equal(t, []string{"200"}, fields[":status"])
		require.Equal(t, []string{"?1"}, fields["capsule-protocol"])
		require.Equal(t, []byte("foobar"), rw.DecodeBody(t))
	})

	t.Run("before sending the response header", func(t *testing.T) {
		rw := newTestResponseWriter(t)
		str := rw.HTTPStream()
		rw.WriteHeader(http.StatusOK)
		_, err := str.Write([]byte("foobar"))
		require.EqualError(t, err, "http3: invalid use of Stream.Write before sending the response header")
		require.EqualError(t,
			str.TryWriteAll([]byte("foobar")),
			"http3: invalid use of Stream.TryWriteAll before sending the response header",
		)
		_, err = rw.Write([]byte("foobar"))
		require.ErrorIs(t, err, http.ErrHijacked)
		require.Zero(t, rw.buf.Len())

		require.NoError(t, rw.FlushError())
		_, err = str.Write([]byte("foobar"))
		require.NoError(t, err)
		require.Equal(t, []string{"200"}, rw.DecodeHeaders(t, 0)[":status"])
		require.Equal(t, []byte("foobar"), rw.DecodeBody(t))
	})

	t.Run("after an informational response", func(t *testing.T) {
		rw := newTestResponseWriter(t)
		rw.WriteHeader(http.StatusEarlyHints)
		l := rw.buf.Len()
		require.NotZero(t, l)
		str := rw.HTTPStream()
		_, err := str.Write([]byte("foobar"))
		require.EqualError(t, err, "http3: invalid use of Stream.Write before sending the response header")
		require.Equal(t, l, rw.buf.Len())
	})

	t.Run("after writing the response body", func(t *testing.T) {
		const msg = "http3: HTTPStream called after writing the response body"
		rw := newTestResponseWriter(t)
		rw.Write([]byte("foobar"))
		// the DATA frame is queued
		require.PanicsWithValue(t, msg, func() { rw.HTTPStream() })
		// the DATA frame was sent
		rw.Flush()
		require.PanicsWithValue(t, msg, func() { rw.HTTPStream() })
		require.False(t, rw.wasStreamHijacked())
	})
}

func TestResponseWriterHeaderRetry(t *testing.T) {
	var buf bytes.Buffer
	mockCtrl := gomock.NewController(t)
	qstr := NewMockDatagramStream(mockCtrl)
	qstr.EXPECT().StreamID().Return(quic.StreamID(42)).AnyTimes()
	gomock.InOrder(
		// the write deadline expires after the first few bytes of the HEADERS frame
		qstr.EXPECT().Write(gomock.Any()).DoAndReturn(func(b []byte) (int, error) {
			buf.Write(b[:3])
			return 3, os.ErrDeadlineExceeded
		}),
		qstr.EXPECT().Write(gomock.Any()).DoAndReturn(buf.Write).AnyTimes(),
	)
	str := newServerStream(qstr, nil, nil, nil)
	rw := newResponseWriter(str, nil, http.MethodGet, nil)
	rw.Header().Set("Foo", "bar")
	rw.WriteHeader(http.StatusOK)

	require.ErrorIs(t, rw.FlushError(), os.ErrDeadlineExceeded)
	_, err := str.Write([]byte("foobar"))
	require.EqualError(t, err, "http3: invalid use of Stream.Write before sending the response header")
	// retry, as an application would after extending the write deadline
	require.NoError(t, rw.FlushError())
	_, err = rw.Write([]byte("foobar"))
	require.NoError(t, err)

	fields := decodeHeader(t, &buf)
	require.Equal(t, []string{"200"}, fields[":status"])
	require.Equal(t, []string{"bar"}, fields["foo"])
	require.Equal(t, getDataFrame([]byte("foobar")), buf.Bytes())
}

func TestResponseWriterDataRetry(t *testing.T) {
	var buf bytes.Buffer
	mockCtrl := gomock.NewController(t)
	qstr := NewMockDatagramStream(mockCtrl)
	qstr.EXPECT().StreamID().Return(quic.StreamID(42)).AnyTimes()
	// the write deadline expires while writing the buffered response body
	qstr.EXPECT().Write([]byte("foo")).DoAndReturn(func(b []byte) (int, error) {
		buf.Write(b[:1])
		return 1, os.ErrDeadlineExceeded
	})
	qstr.EXPECT().Write(gomock.Any()).DoAndReturn(buf.Write).AnyTimes()
	rw := newResponseWriter(newStream(qstr, nil, nil, nil, nil), nil, http.MethodGet, nil)
	_, err := rw.Write([]byte("foo")) // buffered
	require.NoError(t, err)

	data := bytes.Repeat([]byte("a"), maxSmallResponseSize)
	_, err = rw.Write(data)
	require.ErrorIs(t, err, os.ErrDeadlineExceeded)
	// retry, as an application would after extending the write deadline
	_, err = rw.Write(data)
	require.NoError(t, err)

	decodeHeader(t, &buf)
	require.Equal(t, append(getDataFrame([]byte("foo")), getDataFrame(data)...), buf.Bytes())
}

func TestResponseWriterContentLength(t *testing.T) {
	rw := newTestResponseWriter(t)
	rw.Header().Set("Content-Length", "6")
	n, err := rw.Write([]byte("foobar"))
	require.Equal(t, 6, n)
	require.NoError(t, err)

	n, err = rw.Write([]byte{0x42})
	require.Zero(t, n)
	require.ErrorIs(t, err, http.ErrContentLength)

	fields := rw.DecodeHeaders(t, 0)
	require.Equal(t, []string{"200"}, fields[":status"])
	require.Equal(t, []string{"6"}, fields["content-length"])
	require.Equal(t, []byte("foobar"), rw.DecodeBody(t))
}

func TestResponseWriterContentLengthZero(t *testing.T) {
	rw := newTestResponseWriter(t)
	rw.Header().Set("Content-Length", "0")
	n, err := rw.Write([]byte("foobar"))
	require.Zero(t, n)
	require.ErrorIs(t, err, http.ErrContentLength)
	require.NoError(t, rw.Finish())

	fields := rw.DecodeHeaders(t, 0)
	require.Equal(t, []string{"200"}, fields[":status"])
	require.Equal(t, []string{"0"}, fields["content-length"])
	require.Empty(t, rw.DecodeBody(t))
}

func TestResponseWriterConnect(t *testing.T) {
	var buf bytes.Buffer
	mockCtrl := gomock.NewController(t)
	qstr := NewMockDatagramStream(mockCtrl)
	qstr.EXPECT().StreamID().Return(quic.StreamID(42)).AnyTimes()
	qstr.EXPECT().Write(gomock.Any()).DoAndReturn(buf.Write).AnyTimes()
	rw := newResponseWriter(newStream(qstr, nil, nil, nil, nil), nil, http.MethodConnect, nil)
	_, err := rw.Write([]byte("foobar"))
	require.NoError(t, err)
	require.NoError(t, rw.Finish())

	fields := decodeHeader(t, &buf)
	require.Equal(t, []string{"200"}, fields[":status"])
	require.NotContains(t, fields, "content-length")
}

func TestResponseWriterContentLengthRetry(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	qstr := NewMockDatagramStream(mockCtrl)
	qstr.EXPECT().StreamID().Return(quic.StreamID(42)).AnyTimes()
	gomock.InOrder(
		// the write deadline expires before the HEADERS frame is written
		qstr.EXPECT().Write(gomock.Any()).Return(0, os.ErrDeadlineExceeded),
		qstr.EXPECT().Write(gomock.Any()).DoAndReturn(io.Discard.Write).AnyTimes(),
	)
	rw := newResponseWriter(newStream(qstr, nil, nil, nil, nil), nil, http.MethodGet, nil)
	rw.Header().Set("Content-Length", strconv.Itoa(maxSmallResponseSize))

	data := make([]byte, maxSmallResponseSize)
	_, err := rw.Write(data)
	require.ErrorIs(t, err, os.ErrDeadlineExceeded)
	// retry, as an application would after extending the write deadline
	_, err = rw.Write(data)
	require.NoError(t, err)
}

func TestResponseWriterContentTypeSniffing(t *testing.T) {
	t.Run("no content type", func(t *testing.T) {
		testContentTypeSniffing(t, map[string]string{}, "text/html; charset=utf-8")
	})

	t.Run("explicit content type", func(t *testing.T) {
		testContentTypeSniffing(t, map[string]string{"Content-Type": "text/plain"}, "text/plain")
	})

	t.Run("with content encoding", func(t *testing.T) {
		testContentTypeSniffing(t, map[string]string{"Content-Encoding": "gzip"}, "")
	})
}

func testContentTypeSniffing(t *testing.T, hdrs map[string]string, expectedContentType string) {
	rw := newTestResponseWriter(t)
	for k, v := range hdrs {
		rw.Header().Set(k, v)
	}
	rw.Write([]byte("<html></html>"))

	fields := rw.DecodeHeaders(t, 0)
	require.Equal(t, []string{"200"}, fields[":status"])
	if expectedContentType == "" {
		require.NotContains(t, fields, "content-type")
	} else {
		require.Equal(t, []string{expectedContentType}, fields["content-type"])
	}
}

func TestResponseWriterEarlyHints(t *testing.T) {
	rw := newTestResponseWriter(t)
	rw.Header().Add("Link", "</style.css>; rel=preload; as=style")
	rw.Header().Add("Link", "</script.js>; rel=preload; as=script")
	rw.WriteHeader(http.StatusEarlyHints) // status 103

	n, err := rw.Write([]byte("foobar"))
	require.Equal(t, 6, n)
	require.NoError(t, err)

	// Early Hints must have been received
	fields := rw.DecodeHeaders(t, 0)
	require.Len(t, fields, 2)
	require.Equal(t, []string{"103"}, fields[":status"])
	require.Equal(t,
		[]string{"</style.css>; rel=preload; as=style", "</script.js>; rel=preload; as=script"},
		fields["link"],
	)

	// headers sent in the informational response must also be included in the final response
	fields = rw.DecodeHeaders(t, 1)
	require.Len(t, fields, 4)
	require.Equal(t, []string{"200"}, fields[":status"])
	require.Contains(t, fields, "date")
	require.Contains(t, fields, "content-type")
	require.Equal(t,
		[]string{"</style.css>; rel=preload; as=style", "</script.js>; rel=preload; as=script"},
		fields["link"],
	)

	require.Equal(t, []byte("foobar"), rw.DecodeBody(t))
}

func TestResponseWriterTrailers(t *testing.T) {
	rw := newTestResponseWriter(t)

	rw.Header().Add("Trailer", "key, Content-Length, Upgrade") // Content-Length and Upgrade are not valid trailers
	n, err := rw.Write([]byte("foobar"))
	require.Equal(t, 6, n)
	require.NoError(t, err)

	// writeTrailers needs to be called after writing the full body
	headers := rw.DecodeHeaders(t, 0)
	require.Equal(t, []string{"key, Content-Length, Upgrade"}, headers["trailer"])
	require.NotContains(t, headers, "foo")
	require.Equal(t, []byte("foobar"), rw.DecodeBody(t))

	// headers set after writing the body are trailers
	rw.Header().Set("key", "value")                      // announced trailer
	rw.Header().Set("foo", "bar")                        // this trailer was not announced, and will therefore be ignored
	rw.Header().Set(http.TrailerPrefix+"lorem", "ipsum") // unannounced trailer with trailer prefix
	rw.Header().Set("Content-Length", "999")             // invalid trailer, will be ignored
	rw.Header().Set("Upgrade", "foo")                    // connection-specific field, will be ignored
	require.NoError(t, rw.writeTrailers())

	trailers := rw.DecodeHeaders(t, 2)
	require.Equal(t, []string{"value"}, trailers["key"])
	require.Equal(t, []string{"ipsum"}, trailers["lorem"])
	// trailers without the trailer prefix that were not announced are ignored
	require.NotContains(t, trailers, "foo")
	// invalid trailers are ignored
	require.NotContains(t, trailers, "content-length")
	require.NotContains(t, trailers, "upgrade")
}
