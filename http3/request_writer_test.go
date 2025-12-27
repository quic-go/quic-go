package http3

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3/qlog"
	"github.com/quic-go/quic-go/qlogwriter"
	"github.com/quic-go/quic-go/testutils/events"

	"github.com/stretchr/testify/require"
)

func decodeRequest(t *testing.T, str io.Reader, streamID quic.StreamID, eventRecorder *events.Recorder) map[string]string {
	t.Helper()

	r := io.LimitedReader{R: str, N: 1000}
	fp := frameParser{r: &r}
	frame, err := fp.ParseNext(nil)
	require.NoError(t, err)
	require.IsType(t, &headersFrame{}, frame)
	headersFrame := frame.(*headersFrame)
	data := make([]byte, headersFrame.Length)
	_, err = io.ReadFull(&r, data)
	require.NoError(t, err)
	hfs := decodeQpackHeaderFields(t, data)
	values := make(map[string]string)
	for _, hf := range hfs {
		values[hf.Name] = hf.Value
	}

	headerFields := make([]qlog.HeaderField, len(hfs))
	for i, hf := range hfs {
		headerFields[i] = qlog.HeaderField{Name: hf.Name, Value: hf.Value}
	}
	require.Equal(t,
		[]qlogwriter.Event{
			qlog.FrameCreated{
				StreamID: streamID,
				Raw: qlog.RawInfo{
					Length:        int(1000 - r.N),
					PayloadLength: int(headersFrame.Length),
				},
				Frame: qlog.Frame{Frame: qlog.HeadersFrame{HeaderFields: headerFields}},
			},
		},
		eventRecorder.Events(qlog.FrameCreated{}),
	)

	return values
}

func TestRequestWriterGetRequestGzip(t *testing.T) {
	t.Run("gzip", func(t *testing.T) {
		testRequestWriterGzip(t, true)
	})
	t.Run("no gzip", func(t *testing.T) {
		testRequestWriterGzip(t, false)
	})
}

func testRequestWriterGzip(t *testing.T, gzip bool) {
	req := httptest.NewRequest(http.MethodGet, "https://quic-go.net/index.html?foo=bar", nil)
	req.AddCookie(&http.Cookie{Name: "foo", Value: "bar"})
	req.AddCookie(&http.Cookie{Name: "baz", Value: "lorem ipsum"})

	rw := newRequestWriter()
	var eventRecorder events.Recorder
	buf := &bytes.Buffer{}
	require.NoError(t, rw.WriteRequestHeader(buf, req, gzip, 42, &eventRecorder))
	headerFields := decodeRequest(t, buf, 42, &eventRecorder)
	require.Equal(t, "quic-go.net", headerFields[":authority"])
	require.Equal(t, http.MethodGet, headerFields[":method"])
	require.Equal(t, "/index.html?foo=bar", headerFields[":path"])
	require.Equal(t, "https", headerFields[":scheme"])
	require.Equal(t, `foo=bar; baz="lorem ipsum"`, headerFields["cookie"])
	switch gzip {
	case true:
		require.Equal(t, "gzip", headerFields["accept-encoding"])
	case false:
		require.NotContains(t, headerFields, "accept-encoding")
	}
}

func TestRequestWriterInvalidHostHeader(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "https://quic-go.net/index.html?foo=bar", nil)
	req.Host = "foo@bar" // @ is invalid
	rw := newRequestWriter()
	require.EqualError(t,
		rw.WriteRequestHeader(&bytes.Buffer{}, req, false, 0, nil),
		"http3: invalid Host header",
	)
}

func TestRequestWriterConnect(t *testing.T) {
	// httptest.NewRequest does not properly support the CONNECT method
	req, err := http.NewRequest(http.MethodConnect, "https://quic-go.net/", nil)
	require.NoError(t, err)
	rw := newRequestWriter()
	buf := &bytes.Buffer{}
	var eventRecorder events.Recorder
	require.NoError(t, rw.WriteRequestHeader(buf, req, false, 1337, &eventRecorder))
	headerFields := decodeRequest(t, buf, 1337, &eventRecorder)
	require.Equal(t, http.MethodConnect, headerFields[":method"])
	require.Equal(t, "quic-go.net", headerFields[":authority"])
	require.NotContains(t, headerFields, ":path")
	require.NotContains(t, headerFields, ":scheme")
	require.NotContains(t, headerFields, ":protocol")
}

func TestRequestWriterExtendedConnect(t *testing.T) {
	// httptest.NewRequest does not properly support the CONNECT method
	req, err := http.NewRequest(http.MethodConnect, "https://quic-go.net/", nil)
	require.NoError(t, err)
	req.Proto = "webtransport"
	rw := newRequestWriter()
	buf := &bytes.Buffer{}
	var eventRecorder events.Recorder
	require.NoError(t, rw.WriteRequestHeader(buf, req, false, 1234, &eventRecorder))
	headerFields := decodeRequest(t, buf, 1234, &eventRecorder)
	require.Equal(t, "quic-go.net", headerFields[":authority"])
	require.Equal(t, http.MethodConnect, headerFields[":method"])
	require.Equal(t, "/", headerFields[":path"])
	require.Equal(t, "https", headerFields[":scheme"])
	require.Equal(t, "webtransport", headerFields[":protocol"])
}

func TestRequestWriterTrailers(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "https://quic-go.net/upload", nil)
	req.Trailer = http.Header{
		"Trailer1":       []string{"foo"},
		"Trailer2":       []string{"bar"},
		"Content-Length": []string{"42"}, // Content-Length is not a valid trailer
	}

	rw := newRequestWriter()
	buf := &bytes.Buffer{}
	require.NoError(t, rw.WriteRequestHeader(buf, req, false, 42, nil))
	headers := decodeHeader(t, buf)
	require.Len(t, headers["trailer"], 1)
	require.Contains(t, headers["trailer"][0], "Trailer1")
	require.Contains(t, headers["trailer"][0], "Trailer2")
	require.NotContains(t, headers["trailer"][0], "Content-Length")

	require.NoError(t, rw.WriteRequestTrailer(buf, req, 42, nil))

	trailers := decodeHeader(t, buf)
	require.Equal(t, map[string][]string{
		"trailer1": {"foo"},
		"trailer2": {"bar"},
	}, trailers)
}
