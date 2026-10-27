package http3

import (
	"bytes"
	"io"
	"log/slog"
	"net/http"
	"os"
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
	rw := newResponseWriter(
		newStream(str, nil, nil, func(io.Reader, *headersFrame) error { return nil }, &eventRecorder),
		nil,
		false,
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

	fields := rw.DecodeHeaders(t, 0)
	require.Equal(t, []string{"304"}, fields[":status"])
	require.Empty(t, rw.DecodeBody(t))
}

func TestResponseWriterHTTPStream(t *testing.T) {
	t.Run("with WriteHeader", func(t *testing.T) {
		rw := newTestResponseWriter(t)
		rw.Header().Set("Capsule-Protocol", "?1")
		rw.WriteHeader(http.StatusOK)
		str := rw.HTTPStream()
		require.PanicsWithValue(t, "http3: WriteHeader called after HTTPStream", func() { rw.WriteHeader(http.StatusOK) })
		_, err := str.Write([]byte("foobar"))
		require.NoError(t, err)

		fields := rw.DecodeHeaders(t, 0)
		require.Equal(t, []string{"200"}, fields[":status"])
		require.Equal(t, []string{"?1"}, fields["capsule-protocol"])
		require.Equal(t, []byte("foobar"), rw.DecodeBody(t))
	})

	t.Run("without WriteHeader", func(t *testing.T) {
		rw := newTestResponseWriter(t)
		str := rw.HTTPStream()
		require.Zero(t, rw.buf.Len())
		require.PanicsWithValue(t, "http3: WriteHeader called after HTTPStream", func() { rw.WriteHeader(http.StatusOK) })
		_, err := str.Write([]byte("foobar"))
		require.EqualError(t, err, "http3: invalid use of Stream.Write before sending the response header")
		require.EqualError(t,
			str.TryWriteAll([]byte("foobar")),
			"http3: invalid use of Stream.TryWriteAll before sending the response header",
		)
		require.Zero(t, rw.buf.Len())
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
	rw := newResponseWriter(newStream(qstr, nil, nil, nil, nil), nil, false, nil)
	rw.Header().Set("Foo", "bar")
	rw.WriteHeader(http.StatusOK)

	require.ErrorIs(t, rw.FlushError(), os.ErrDeadlineExceeded)
	// retry, as an application would after extending the write deadline
	require.NoError(t, rw.FlushError())
	_, err := rw.Write([]byte("foobar"))
	require.NoError(t, err)

	fields := decodeHeader(t, &buf)
	require.Equal(t, []string{"200"}, fields[":status"])
	require.Equal(t, []string{"bar"}, fields["foo"])
	require.Equal(t, getDataFrame([]byte("foobar")), buf.Bytes())
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

	rw.Header().Add("Trailer", "key, Content-Length") // Content-Length is not a valid trailer
	n, err := rw.Write([]byte("foobar"))
	require.Equal(t, 6, n)
	require.NoError(t, err)

	// writeTrailers needs to be called after writing the full body
	headers := rw.DecodeHeaders(t, 0)
	require.Equal(t, []string{"key, Content-Length"}, headers["trailer"])
	require.NotContains(t, headers, "foo")
	require.Equal(t, []byte("foobar"), rw.DecodeBody(t))

	// headers set after writing the body are trailers
	rw.Header().Set("key", "value")                      // announced trailer
	rw.Header().Set("foo", "bar")                        // this trailer was not announced, and will therefore be ignored
	rw.Header().Set(http.TrailerPrefix+"lorem", "ipsum") // unannounced trailer with trailer prefix
	rw.Header().Set("Content-Length", "999")             // invalid trailer, will be ignored
	require.NoError(t, rw.writeTrailers())

	trailers := rw.DecodeHeaders(t, 2)
	require.Equal(t, []string{"value"}, trailers["key"])
	require.Equal(t, []string{"ipsum"}, trailers["lorem"])
	// trailers without the trailer prefix that were not announced are ignored
	require.NotContains(t, trailers, "foo")
	// invalid trailers are ignored
	require.NotContains(t, trailers, "content-length")
}
