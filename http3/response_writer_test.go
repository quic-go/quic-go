package http3

import (
	"bytes"
	"github.com/Noooste/fhttp"
	"io"
	"testing"

	mockquic "github.com/Noooste/quic-go/internal/mocks/quic"

	"github.com/quic-go/qpack"

	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

type testResponseWriter struct {
	*responseWriter
	buf *bytes.Buffer
}

func (rw *testResponseWriter) DecodeHeaders(t *testing.T) map[string][]string {
	t.Helper()

	rw.Flush()
	rw.flushTrailers()
	fields := make(map[string][]string)
	decoder := qpack.NewDecoder(nil)

	frame, err := (&frameParser{r: rw.buf}).ParseNext()
	require.NoError(t, err)
	require.IsType(t, &headersFrame{}, frame)
	data := make([]byte, frame.(*headersFrame).Length)
	_, err = io.ReadFull(rw.buf, data)
	require.NoError(t, err)
	hfs, err := decoder.DecodeFull(data)
	require.NoError(t, err)
	for _, p := range hfs {
		fields[p.Name] = append(fields[p.Name], p.Value)
	}
	return fields
}

func (rw *testResponseWriter) DecodeBody(t *testing.T) []byte {
	t.Helper()

	frame, err := (&frameParser{r: rw.buf}).ParseNext()
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
	buf := &bytes.Buffer{}
	mockCtrl := gomock.NewController(t)
	str := mockquic.NewMockStream(mockCtrl)
	str.EXPECT().Write(gomock.Any()).DoAndReturn(buf.Write).AnyTimes()
	str.EXPECT().SetReadDeadline(gomock.Any()).Return(nil).AnyTimes()
	str.EXPECT().SetWriteDeadline(gomock.Any()).Return(nil).AnyTimes()
	rw := newResponseWriter(newStream(str, nil, nil, func(r io.Reader, u uint64) error { return nil }), nil, false, nil)
	return &testResponseWriter{responseWriter: rw, buf: buf}
}

func TestResponseWriterInvalidStatus(t *testing.T) {
	rw := newTestResponseWriter(t)
	require.Panics(t, func() { rw.WriteHeader(99) })
	require.Panics(t, func() { rw.WriteHeader(1000) })
}

func TestResponseWriterHeader(t *testing.T) {
	rw := newTestResponseWriter(t)
	rw.Header().Add("Content-Length", "42")
	rw.WriteHeader(http.StatusTeapot) // 418
	// repeated WriteHeader calls are ignored
	rw.WriteHeader(http.StatusInternalServerError)

	// set cookies
	http.SetCookie(rw, &http.Cookie{Name: "foo", Value: "bar"})
	http.SetCookie(rw, &http.Cookie{Name: "baz", Value: "lorem ipsum"})
	// write some data
	rw.Write([]byte("foobar"))

	fields := rw.DecodeHeaders(t)
	require.Equal(t, []string{"418"}, fields[":status"])
	require.Equal(t, []string{"42"}, fields["content-length"])
	require.Equal(t,
		[]string{"foo=bar", `baz="lorem ipsum"`},
		fields["set-cookie"],
	)
	require.Equal(t, []byte("foobar"), rw.DecodeBody(t))
}

func TestResponseWriterDataWithoutHeader(t *testing.T) {
	rw := newTestResponseWriter(t)
	rw.Write([]byte("foobar"))

	fields := rw.DecodeHeaders(t)
	require.Equal(t, []string{"200"}, fields[":status"])
	require.Equal(t, []byte("foobar"), rw.DecodeBody(t))
}

func TestResponseWriterDataStatusWithoutBody(t *testing.T) {
	rw := newTestResponseWriter(t)
	rw.WriteHeader(http.StatusNotModified)
	n, err := rw.Write([]byte("foobar"))
	require.Zero(t, n)
	require.ErrorIs(t, err, http.ErrBodyNotAllowed)

	fields := rw.DecodeHeaders(t)
	require.Equal(t, []string{"304"}, fields[":status"])
	require.Empty(t, rw.DecodeBody(t))
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

	fields := rw.DecodeHeaders(t)
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

	fields := rw.DecodeHeaders(t)
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
	fields := rw.DecodeHeaders(t)
	require.Equal(t, 2, len(fields))
	require.Equal(t, []string{"103"}, fields[":status"])
	require.Equal(t,
		[]string{"</style.css>; rel=preload; as=style", "</script.js>; rel=preload; as=script"},
		fields["link"],
	)

	// headers sent in the informational response must also be included in the final response
	fields = rw.DecodeHeaders(t)
	require.Equal(t, 4, len(fields))
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

	rw.Header().Add("Trailer", "key")
	n, err := rw.Write([]byte("foobar"))
	require.Equal(t, 6, n)
	require.NoError(t, err)

	// writeTrailers needs to be called after writing the full body
	headers := rw.DecodeHeaders(t)
	require.Equal(t, []string{"key"}, headers["trailer"])
	require.NotContains(t, headers, "foo")
	require.Equal(t, []byte("foobar"), rw.DecodeBody(t))

	// headers set after writing the body are trailers
	rw.Header().Set("key", "value")                      // announced trailer
	rw.Header().Set("foo", "bar")                        // this trailer was not announced, and will therefore be ignored
	rw.Header().Set(http.TrailerPrefix+"lorem", "ipsum") // unannounced trailer with trailer prefix
	require.NoError(t, rw.writeTrailers())

	trailers := rw.DecodeHeaders(t)
	require.Equal(t, []string{"value"}, trailers["key"])
	require.Equal(t, []string{"ipsum"}, trailers["lorem"])
	// trailers without the trailer prefix that were not announced are ignored
	require.NotContains(t, trailers, "foo")
}
