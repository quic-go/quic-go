package http3

import (
	"bytes"
	"github.com/Noooste/fhttp"
	"io"
	"net/http/httptest"
	"testing"

	"github.com/quic-go/qpack"

	"github.com/stretchr/testify/require"
)

func decodeRequest(t *testing.T, str io.Reader) map[string]string {
	t.Helper()
	fp := frameParser{r: str}
	frame, err := fp.ParseNext()
	require.NoError(t, err)
	require.IsType(t, &headersFrame{}, frame)
	headersFrame := frame.(*headersFrame)
	data := make([]byte, headersFrame.Length)
	_, err = io.ReadFull(str, data)
	require.NoError(t, err)
	decoder := qpack.NewDecoder(nil)
	hfs, err := decoder.DecodeFull(data)
	require.NoError(t, err)
	values := make(map[string]string)
	for _, hf := range hfs {
		values[hf.Name] = hf.Value
	}
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
	buf := &bytes.Buffer{}
	require.NoError(t, rw.WriteRequestHeader(buf, req, gzip))
	headerFields := decodeRequest(t, buf)
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
		rw.WriteRequestHeader(&bytes.Buffer{}, req, false),
		"http3: invalid Host header",
	)
}

func TestRequestWriterConnect(t *testing.T) {
	// httptest.NewRequest does not properly support the CONNECT method
	req, err := http.NewRequest(http.MethodConnect, "https://quic-go.net/", nil)
	require.NoError(t, err)
	rw := newRequestWriter()
	buf := &bytes.Buffer{}
	require.NoError(t, rw.WriteRequestHeader(buf, req, false))
	headerFields := decodeRequest(t, buf)
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
	require.NoError(t, rw.WriteRequestHeader(buf, req, false))
	headerFields := decodeRequest(t, buf)
	require.Equal(t, "quic-go.net", headerFields[":authority"])
	require.Equal(t, http.MethodConnect, headerFields[":method"])
	require.Equal(t, "/", headerFields[":path"])
	require.Equal(t, "https", headerFields[":scheme"])
	require.Equal(t, "webtransport", headerFields[":protocol"])
}
