package http3

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"testing"

	ossfuzzseeds "github.com/quic-go/go-ossfuzz-seeds"
	"github.com/quic-go/qpack"

	"github.com/stretchr/testify/require"
	"golang.org/x/net/http/httpguts"
)

func decodeFromSlice(headers []qpack.HeaderField) qpack.DecodeFunc {
	var i int
	return func() (qpack.HeaderField, error) {
		if i >= len(headers) {
			return qpack.HeaderField{}, io.EOF
		}
		h := headers[i]
		i++
		return h, nil
	}
}

func TestRequestHeaderParsing(t *testing.T) {
	t.Run("regular path", func(t *testing.T) {
		testRequestHeaderParsing(t, "/foo")
	})

	// see https://github.com/quic-go/quic-go/pull/1898
	t.Run("path starting with //", func(t *testing.T) {
		testRequestHeaderParsing(t, "//foo")
	})
}

func testRequestHeaderParsing(t *testing.T, path string) {
	headers := []qpack.HeaderField{
		{Name: ":scheme", Value: "https"},
		{Name: ":path", Value: path},
		{Name: ":authority", Value: "quic-go.net:443"},
		{Name: ":method", Value: http.MethodGet},
		{Name: "content-length", Value: "42"},
	}
	req, err := requestFromHeaders(decodeFromSlice(headers), math.MaxInt, nil)
	require.NoError(t, err)
	require.Equal(t, http.MethodGet, req.Method)
	require.Equal(t, path, req.URL.Path)
	require.Equal(t, "quic-go.net:443", req.URL.Host)
	require.Equal(t, "HTTP/3.0", req.Proto)
	require.Equal(t, 3, req.ProtoMajor)
	require.Zero(t, req.ProtoMinor)
	require.Equal(t, int64(42), req.ContentLength)
	require.Equal(t, 1, len(req.Header))
	require.Equal(t, "42", req.Header.Get("Content-Length"))
	require.Nil(t, req.Body)
	require.Equal(t, "quic-go.net:443", req.Host)
	require.Equal(t, path, req.RequestURI)
	require.Equal(t, "quic-go.net", req.URL.Hostname())
	require.Equal(t, "https", req.URL.Scheme)
	require.Equal(t, "443", req.URL.Port())
}

func TestRequestHeadersContentLength(t *testing.T) {
	t.Run("no content length", func(t *testing.T) {
		headers := []qpack.HeaderField{
			{Name: ":path", Value: "/"},
			{Name: ":authority", Value: "quic-go.net"},
			{Name: ":method", Value: http.MethodGet},
		}
		req, err := requestFromHeaders(decodeFromSlice(headers), math.MaxInt, nil)
		require.NoError(t, err)
		require.Equal(t, int64(-1), req.ContentLength)
	})

	t.Run("multiple content lengths", func(t *testing.T) {
		headers := []qpack.HeaderField{
			{Name: ":path", Value: "/"},
			{Name: ":authority", Value: "quic-go.net"},
			{Name: ":method", Value: http.MethodGet},
			{Name: "content-length", Value: "42"},
			{Name: "content-length", Value: "42"},
		}
		req, err := requestFromHeaders(decodeFromSlice(headers), math.MaxInt, nil)
		require.NoError(t, err)
		require.Equal(t, "42", req.Header.Get("Content-Length"))
	})
}

func TestRequestHeadersContentLengthValidation(t *testing.T) {
	for _, tc := range []struct {
		name        string
		headers     []qpack.HeaderField
		err         string
		errContains string
	}{
		{
			name: "negative content length",
			headers: []qpack.HeaderField{
				{Name: "content-length", Value: "-42"},
			},
			errContains: "invalid content length",
		},
		{
			name: "multiple differing content lengths",
			headers: []qpack.HeaderField{
				{Name: "content-length", Value: "42"},
				{Name: "content-length", Value: "1337"},
			},
			err: "contradicting content lengths (42 and 1337)",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := requestFromHeaders(decodeFromSlice(tc.headers), math.MaxInt, nil)
			if tc.errContains != "" {
				require.ErrorContains(t, err, tc.errContains)
			}
			if tc.err != "" {
				require.EqualError(t, err, tc.err)
			}
		})
	}
}

func TestRequestHeadersValidation(t *testing.T) {
	for _, tc := range []struct {
		name        string
		headers     []qpack.HeaderField
		err         string
		errContains string
	}{
		{
			name: "upper-case field name",
			headers: []qpack.HeaderField{
				{Name: "Content-Length", Value: "42"},
			},
			err: "header field is not lower-case: Content-Length",
		},
		{
			name: "unknown pseudo header",
			headers: []qpack.HeaderField{
				{Name: ":foo", Value: "bar"},
			},
			err: "unknown pseudo header: :foo",
		},
		{
			name: "pseudo header after regular header",
			headers: []qpack.HeaderField{
				{Name: ":path", Value: "/foo"},
				{Name: "content-length", Value: "42"},
				{Name: ":authority", Value: "quic-go.net"},
			},
			err: "received pseudo header :authority after a regular header field",
		},
		{
			name: "invalid field name",
			headers: []qpack.HeaderField{
				{Name: "@", Value: "42"},
			},
			err: `invalid header field name: "@"`,
		},
		{
			name: "invalid field value",
			headers: []qpack.HeaderField{
				{Name: "content", Value: "\n"},
			},
			err: `invalid header field value for content: "\n"`,
		},
		{
			name: ":status header field", // :status is a response pseudo header
			headers: []qpack.HeaderField{
				{Name: ":status", Value: "404"},
			},
			err: "invalid request pseudo header: :status",
		},
		{
			name: "missing :path",
			headers: []qpack.HeaderField{
				{Name: ":authority", Value: "quic-go.net"},
				{Name: ":method", Value: http.MethodGet},
			},
			err: ":path, :authority and :method must not be empty",
		},
		{
			name: "missing :authority",
			headers: []qpack.HeaderField{
				{Name: ":path", Value: "/foo"},
				{Name: ":method", Value: http.MethodGet},
			},
			err: ":path, :authority and :method must not be empty",
		},
		{
			name: "missing :method",
			headers: []qpack.HeaderField{
				{Name: ":path", Value: "/foo"},
				{Name: ":authority", Value: "quic-go.net"},
			},
			err: ":path, :authority and :method must not be empty",
		},
		{
			name: "duplicate :path",
			headers: []qpack.HeaderField{
				{Name: ":path", Value: "/foo"},
				{Name: ":path", Value: "/foo"},
			},
			err: "duplicate pseudo header: :path",
		},
		{
			name: "duplicate :authority",
			headers: []qpack.HeaderField{
				{Name: ":authority", Value: "quic-go.net"},
				{Name: ":authority", Value: "quic-go.net"},
			},
			err: "duplicate pseudo header: :authority",
		},
		{
			name: "duplicate :method",
			headers: []qpack.HeaderField{
				{Name: ":method", Value: http.MethodGet},
				{Name: ":method", Value: http.MethodGet},
			},
			err: "duplicate pseudo header: :method",
		},
		{
			name: "invalid :protocol",
			headers: []qpack.HeaderField{
				{Name: ":path", Value: "/foo"},
				{Name: ":authority", Value: "quic-go.net"},
				{Name: ":method", Value: http.MethodGet},
				{Name: ":protocol", Value: "connect-udp"},
			},
			err: ":protocol must be empty",
		},
		{
			name: "invalid :path",
			headers: []qpack.HeaderField{
				{Name: ":path", Value: "invalid path"},
				{Name: ":authority", Value: "quic-go.net"},
				{Name: ":method", Value: http.MethodGet},
			},
			errContains: "invalid request URI",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := requestFromHeaders(decodeFromSlice(tc.headers), math.MaxInt, nil)
			if tc.errContains != "" {
				require.ErrorContains(t, err, tc.errContains)
			}
			if tc.err != "" {
				require.EqualError(t, err, tc.err)
			}
			require.NotErrorAs(t, err, new(*qpackError))
		})
	}
}

func TestCookieHeader(t *testing.T) {
	headers := []qpack.HeaderField{
		{Name: ":path", Value: "/foo"},
		{Name: ":authority", Value: "quic-go.net"},
		{Name: ":method", Value: http.MethodGet},
		{Name: "cookie", Value: "cookie1=foobar1"},
		{Name: "cookie", Value: "cookie2=foobar2"},
	}
	req, err := requestFromHeaders(decodeFromSlice(headers), math.MaxInt, nil)
	require.NoError(t, err)
	require.Equal(t, http.Header{
		"Cookie": []string{"cookie1=foobar1; cookie2=foobar2"},
	}, req.Header)
}

func TestHeadersConcatenation(t *testing.T) {
	headers := []qpack.HeaderField{
		{Name: ":path", Value: "/foo"},
		{Name: ":authority", Value: "quic-go.net"},
		{Name: ":method", Value: http.MethodGet},
		{Name: "cache-control", Value: "max-age=0"},
		{Name: "duplicate-header", Value: "1"},
		{Name: "duplicate-header", Value: "2"},
	}
	req, err := requestFromHeaders(decodeFromSlice(headers), math.MaxInt, nil)
	require.NoError(t, err)
	require.Equal(t, http.Header{
		"Cache-Control":    []string{"max-age=0"},
		"Duplicate-Header": []string{"1", "2"},
	}, req.Header)
}

func TestRequestHeadersConnect(t *testing.T) {
	headers := []qpack.HeaderField{
		{Name: ":authority", Value: "quic-go.net"},
		{Name: ":method", Value: http.MethodConnect},
	}
	req, err := requestFromHeaders(decodeFromSlice(headers), math.MaxInt, nil)
	require.NoError(t, err)
	require.Equal(t, http.MethodConnect, req.Method)
	require.Equal(t, "HTTP/3.0", req.Proto)
	require.Equal(t, "quic-go.net", req.RequestURI)
}

func TestRequestHeadersConnectValidation(t *testing.T) {
	for _, tc := range []struct {
		name    string
		headers []qpack.HeaderField
		err     string
	}{
		{
			name: "missing :authority",
			headers: []qpack.HeaderField{
				{Name: ":method", Value: http.MethodConnect},
			},
			err: ":path must be empty and :authority must not be empty",
		},
		{
			name: ":path set",
			headers: []qpack.HeaderField{
				{Name: ":path", Value: "/foo"},
				{Name: ":method", Value: http.MethodConnect},
			},
			err: ":path must be empty and :authority must not be empty",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := requestFromHeaders(decodeFromSlice(tc.headers), math.MaxInt, nil)
			require.EqualError(t, err, tc.err)
		})
	}
}

func TestRequestHeadersExtendedConnect(t *testing.T) {
	headers := []qpack.HeaderField{
		{Name: ":protocol", Value: "webtransport"},
		{Name: ":scheme", Value: "ftp"},
		{Name: ":method", Value: http.MethodConnect},
		{Name: ":authority", Value: "quic-go.net"},
		{Name: ":path", Value: "/foo?val=1337"},
	}
	req, err := requestFromHeaders(decodeFromSlice(headers), math.MaxInt, nil)
	require.NoError(t, err)
	require.Equal(t, http.MethodConnect, req.Method)
	require.Equal(t, "webtransport", req.Proto)
	require.Equal(t, "ftp://quic-go.net/foo?val=1337", req.URL.String())
	require.Equal(t, "1337", req.URL.Query().Get("val"))
}

func TestRequestHeadersExtendedConnectRequestValidation(t *testing.T) {
	headers := []qpack.HeaderField{
		{Name: ":protocol", Value: "webtransport"},
		{Name: ":method", Value: http.MethodConnect},
		{Name: ":authority", Value: "quic.clemente.io"},
		{Name: ":path", Value: "/foo"},
	}
	_, err := requestFromHeaders(decodeFromSlice(headers), math.MaxInt, nil)
	require.EqualError(t, err, "extended CONNECT: :scheme, :path and :authority must not be empty")
}

func TestRequestHeadersExtendedConnectInvalidProtocol(t *testing.T) {
	headers := []qpack.HeaderField{
		{Name: ":protocol", Value: "HTTP/3.0"},
		{Name: ":scheme", Value: "https"},
		{Name: ":method", Value: http.MethodConnect},
		{Name: ":authority", Value: "quic-go.net"},
		{Name: ":path", Value: "/foo"},
	}
	_, err := requestFromHeaders(decodeFromSlice(headers), math.MaxInt, nil)
	require.EqualError(t, err, `invalid :protocol: "HTTP/3.0"`)
}

func TestResponseHeaderParsing(t *testing.T) {
	headers := []qpack.HeaderField{
		{Name: ":status", Value: "200"},
		{Name: "content-length", Value: "42"},
	}
	rsp := &http.Response{}
	require.NoError(t, updateResponseFromHeaders(rsp, decodeFromSlice(headers), math.MaxInt, nil))
	require.Equal(t, "HTTP/3.0", rsp.Proto)
	require.Equal(t, 3, rsp.ProtoMajor)
	require.Zero(t, rsp.ProtoMinor)
	require.Equal(t, int64(42), rsp.ContentLength)
	require.Equal(t, 1, len(rsp.Header))
	require.Equal(t, "42", rsp.Header.Get("Content-Length"))
	require.Nil(t, rsp.Body)
	require.Equal(t, 200, rsp.StatusCode)
	require.Equal(t, "200 OK", rsp.Status)
}

func TestResponseHeaderParsingValidation(t *testing.T) {
	for _, tc := range []struct {
		name        string
		headers     []qpack.HeaderField
		err         string
		errContains string
	}{
		{
			name: "missing :status",
			headers: []qpack.HeaderField{
				{Name: "content-length", Value: "42"},
			},
			err: "missing :status field",
		},
		{
			name: "invalid status code",
			headers: []qpack.HeaderField{
				{Name: ":status", Value: "foobar"},
			},
			errContains: "invalid status code",
		},
		{
			name: ":method header field", // :method is a request pseudo header
			headers: []qpack.HeaderField{
				{Name: ":method", Value: http.MethodGet},
			},
			err: "invalid response pseudo header: :method",
		},
		{
			name: "duplicate :status",
			headers: []qpack.HeaderField{
				{Name: ":status", Value: "200"},
				{Name: ":status", Value: "404"},
			},
			err: "duplicate pseudo header: :status",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := updateResponseFromHeaders(&http.Response{}, decodeFromSlice(tc.headers), math.MaxInt, nil)
			if tc.errContains != "" {
				require.ErrorContains(t, err, tc.errContains)
			}
			if tc.err != "" {
				require.EqualError(t, err, tc.err)
			}
		})
	}

	for _, tc := range []struct {
		name         string
		invalidField string
	}{
		{name: "connection", invalidField: "connection"},
		{name: "keep-alive", invalidField: "keep-alive"},
		{name: "proxy-connection", invalidField: "proxy-connection"},
		{name: "transfer-encoding", invalidField: "transfer-encoding"},
		{name: "upgrade", invalidField: "upgrade"},
	} {
		t.Run("invalid field: "+tc.name, func(t *testing.T) {
			headers := []qpack.HeaderField{
				{Name: ":status", Value: "404"},
				{Name: tc.invalidField, Value: "some-value"},
			}
			err := updateResponseFromHeaders(&http.Response{}, decodeFromSlice(headers), math.MaxInt, nil)
			require.EqualError(t, err, fmt.Sprintf("invalid header field name: %q", tc.invalidField))
		})
	}
}

func TestResponseTrailerFields(t *testing.T) {
	headers := []qpack.HeaderField{
		{Name: ":status", Value: "200"},
		{Name: "trailer", Value: "Trailer1, Trailer2"},
		{Name: "trailer", Value: "TRAILER3"},
	}
	var rsp http.Response
	require.NoError(t, updateResponseFromHeaders(&rsp, decodeFromSlice(headers), math.MaxInt, nil))
	require.Equal(t, 0, len(rsp.Header))
	require.Equal(t, http.Header(map[string][]string{
		"Trailer1": nil,
		"Trailer2": nil,
		"Trailer3": nil,
	}), rsp.Trailer)
}

func TestResponseTrailerParsingTE(t *testing.T) {
	headers := []qpack.HeaderField{
		{Name: ":status", Value: "404"},
		{Name: "te", Value: "trailers"},
	}
	require.NoError(t, updateResponseFromHeaders(&http.Response{}, decodeFromSlice(headers), math.MaxInt, nil))
	headers = []qpack.HeaderField{
		{Name: ":status", Value: "404"},
		{Name: "te", Value: "not-trailers"},
	}
	require.EqualError(t,
		updateResponseFromHeaders(&http.Response{}, decodeFromSlice(headers), math.MaxInt, nil),
		`invalid TE header field value: "not-trailers"`)
}

func TestResponseTrailerParsing(t *testing.T) {
	trailerHdr, err := parseTrailers(decodeFromSlice([]qpack.HeaderField{
		{Name: "foo", Value: "42"},
	}), math.MaxInt, nil)
	require.NoError(t, err)
	require.Equal(t, "42", trailerHdr.Get("Foo"))
}

func TestResponseTrailerParsingValidation(t *testing.T) {
	for _, tc := range []struct {
		name        string
		headers     []qpack.HeaderField
		sizeLimit   int
		err         string
		errContains string
		errIs       error
	}{
		{
			name: "field list too large",
			headers: []qpack.HeaderField{
				{Name: "foo", Value: "bar"},
			},
			sizeLimit: 5,
			errIs:     errHeaderTooLarge,
		},
		{
			name: "upper-case field name",
			headers: []qpack.HeaderField{
				{Name: "Foo", Value: "bar"},
			},
			err: "header field is not lower-case: Foo",
		},
		{
			name: "pseudo header",
			headers: []qpack.HeaderField{
				{Name: ":status", Value: "200"},
			},
			err: "http3: received pseudo header in trailer: :status",
		},
		{
			name: "invalid field name",
			headers: []qpack.HeaderField{
				{Name: "@", Value: "bar"},
			},
			err: `invalid header field name: "@"`,
		},
		{
			name: "invalid field value",
			headers: []qpack.HeaderField{
				{Name: "foo", Value: "\n"},
			},
			err: `invalid header field value for foo: "\n"`,
		},
		{
			name: "connection-specific field",
			headers: []qpack.HeaderField{
				{Name: "connection", Value: "close"},
			},
			err: `invalid header field name: "connection"`,
		},
		{
			name: "invalid te field value",
			headers: []qpack.HeaderField{
				{Name: "te", Value: "gzip"},
			},
			err: `invalid TE header field value: "gzip"`,
		},
		{
			name: "invalid trailer field",
			headers: []qpack.HeaderField{
				{Name: "content-length", Value: "42"},
			},
			err: `invalid trailer field name: "content-length"`,
		},
		{
			name: "valid header field name disallowed in trailers",
			headers: []qpack.HeaderField{
				{Name: "if-match", Value: "etag"},
			},
			err: `invalid trailer field name: "if-match"`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sizeLimit := tc.sizeLimit
			if sizeLimit == 0 {
				sizeLimit = math.MaxInt
			}
			_, err := parseTrailers(decodeFromSlice(tc.headers), sizeLimit, nil)
			if tc.errIs != nil {
				require.ErrorIs(t, err, tc.errIs)
			}
			if tc.errContains != "" {
				require.ErrorContains(t, err, tc.errContains)
			}
			if tc.err != "" {
				require.EqualError(t, err, tc.err)
			}
			require.NotErrorAs(t, err, new(*qpackError))
		})
	}
}

func TestQpackError(t *testing.T) {
	buf := &bytes.Buffer{}
	enc := qpack.NewEncoder(buf)
	enc.WriteField(qpack.HeaderField{Name: ":status", Value: "200"})
	enc.Close()

	t.Run("header parsing", func(t *testing.T) {
		dec := qpack.NewDecoder()
		decodeFn := dec.Decode(buf.Bytes()[:len(buf.Bytes())/2])
		_, err := requestFromHeaders(decodeFn, math.MaxInt, nil)
		require.ErrorAs(t, err, new(*qpackError))
	})

	t.Run("trailer parsing", func(t *testing.T) {
		dec := qpack.NewDecoder()
		decodeFn := dec.Decode(buf.Bytes()[:len(buf.Bytes())/2])
		err := updateResponseFromHeaders(&http.Response{}, decodeFn, math.MaxInt, nil)
		require.ErrorAs(t, err, new(*qpackError))
	})
}

func BenchmarkRequestFromHeaders(b *testing.B) {
	b.ReportAllocs()

	headers := []qpack.HeaderField{
		{Name: ":path", Value: "/api/v1/users/12345"},
		{Name: ":authority", Value: "quic-go.net"},
		{Name: ":method", Value: http.MethodPost},
		{Name: "content-type", Value: "application/json"},
		{Name: "content-length", Value: "1024"},
		{Name: "user-agent", Value: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.0 Safari/605.1.15"},
		{Name: "accept", Value: "application/json, text/plain, */*"},
		{Name: "accept-encoding", Value: "gzip, deflate, br"},
		{Name: "accept-language", Value: "en-US,en;q=0.9"},
		{Name: "cache-control", Value: "no-cache"},
		{Name: "cookie", Value: "session_id=abc123"},
		{Name: "cookie", Value: "user_pref=dark_mode"},
		{Name: "referer", Value: "https://quic-go.net/docs/http3/"},
	}
	var buf bytes.Buffer
	enc := qpack.NewEncoder(&buf)
	for _, hf := range headers {
		require.NoError(b, enc.WriteField(hf))
	}

	dec := qpack.NewDecoder()
	for b.Loop() {
		decodeFn := dec.Decode(buf.Bytes())
		if _, err := requestFromHeaders(decodeFn, math.MaxInt, nil); err != nil {
			b.Fatalf("failed to parse request: %v", err)
		}
	}
}

func FuzzHeaderParsing(f *testing.F) {
	corpus := ossfuzzseeds.New(f)

	for _, s := range [][]qpack.HeaderField{
		{ // GET request
			{Name: ":method", Value: "GET"},
			{Name: ":scheme", Value: "https"},
			{Name: ":path", Value: "/"},
			{Name: ":authority", Value: "example.com"},
		},
		{ // POST with Content-Length
			{Name: ":method", Value: "POST"},
			{Name: ":scheme", Value: "https"},
			{Name: ":path", Value: "/submit"},
			{Name: ":authority", Value: "example.com"},
			{Name: "content-length", Value: "42"},
			{Name: "content-type", Value: "application/json"},
		},
		{ // CONNECT request
			{Name: ":method", Value: "CONNECT"},
			{Name: ":authority", Value: "proxy.example.com:443"},
		},
		{ // extended CONNECT
			{Name: ":method", Value: "CONNECT"},
			{Name: ":scheme", Value: "https"},
			{Name: ":path", Value: "/webtransport"},
			{Name: ":authority", Value: "example.com"},
			{Name: ":protocol", Value: "webtransport"},
		},
		{ // 200 response
			{Name: ":status", Value: "200"},
			{Name: "content-type", Value: "text/html"},
			{Name: "content-length", Value: "1024"},
		},
		{ // response with trailer announcement
			{Name: ":status", Value: "200"},
			{Name: "trailer", Value: "Checksum"},
		},
	} {
		seedsStrings := make([][2]string, len(s))
		for i, h := range s {
			seedsStrings[i] = [2]string{h.Name, h.Value}
		}
		data, err := json.Marshal(seedsStrings)
		require.NoError(f, err)
		corpus.Add(data)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		// Header fields are encoded as JSON (a [][2]string of [name, value] pairs) rather than as
		// QPACK-encoded bytes. This bypasses the QPACK decoder intentionally: QPACK is fuzzed
		// separately (in the qpack package).
		const maxPairs = 1000
		const maxHeaderBytes = 50_000
		var pairs [][2]string
		if err := json.Unmarshal(data, &pairs); err != nil {
			return
		}
		if len(pairs) > maxPairs {
			// don't fuzz too many header fields all at once
			return
		}
		headers := make([]qpack.HeaderField, len(pairs))
		for i, p := range pairs {
			headers[i] = qpack.HeaderField{Name: p[0], Value: p[1]}
		}

		if req, err := requestFromHeaders(decodeFromSlice(headers), maxHeaderBytes, nil); err == nil {
			require.NotEmpty(t, req.Method, "request has empty Method")
			require.NotNil(t, req.URL, "request has nil URL")
			require.NotEmpty(t, req.Proto, "request has empty Proto")
			require.Truef(t, req.ProtoMajor == 3 && req.ProtoMinor == 0, "expected HTTP/3.0, got %d.%d", req.ProtoMajor, req.ProtoMinor)
			require.GreaterOrEqualf(t, req.ContentLength, int64(-1), "invalid ContentLength: %d", req.ContentLength)
			require.NotNil(t, req.Header, "request has nil Header map")
			if req.Method == http.MethodConnect && req.Proto == "HTTP/3.0" {
				// regular CONNECT: :path must be empty, :authority must be set
				require.Empty(t, req.URL.Path, "CONNECT request has non-empty URL.Path")
			}
			if req.Method != http.MethodConnect {
				require.NotEmpty(t, req.Host, "non-CONNECT request has empty Host")
				require.NotEmpty(t, req.RequestURI, "non-CONNECT request has empty RequestURI")
			}
			requireValidFuzzHeader(t, req.Header, "request")
		}

		rsp := &http.Response{}
		if err := updateResponseFromHeaders(rsp, decodeFromSlice(headers), maxHeaderBytes, nil); err == nil {
			require.Equalf(t, "HTTP/3.0", rsp.Proto, "expected Proto HTTP/3.0, got %q", rsp.Proto)
			require.Equalf(t, 3, rsp.ProtoMajor, "expected ProtoMajor 3, got %d", rsp.ProtoMajor)
			require.GreaterOrEqualf(t, rsp.ContentLength, int64(-1), "invalid ContentLength: %d", rsp.ContentLength)
			require.NotNil(t, rsp.Header, "response has nil Header map")
			require.NotEmpty(t, rsp.Status, "response has empty Status")
			requireValidFuzzHeader(t, rsp.Header, "response")
		}

		if trailers, err := parseTrailers(decodeFromSlice(headers), maxHeaderBytes, nil); err == nil {
			for name := range trailers {
				require.Falsef(t, len(name) > 0 && name[0] == ':', "trailer contains pseudo header %q", name)
			}
			requireValidFuzzTrailer(t, trailers)
		}
	})
}

func requireValidFuzzHeader(t *testing.T, h http.Header, context string) {
	t.Helper()
	for name, values := range h {
		require.Truef(t, httpguts.ValidHeaderFieldName(name), "%s contains invalid header field name %q", context, name)
		for _, value := range values {
			require.Truef(t, httpguts.ValidHeaderFieldValue(value), "%s contains invalid header field value for %q: %q", context, name, value)
		}
	}
	for _, name := range invalidHeaderFields {
		require.Emptyf(t, h.Get(name), "%s contains connection-specific header %q", context, name)
	}
	if te := h.Values("Te"); len(te) > 0 {
		for _, value := range te {
			require.Equalf(t, "trailers", value, "%s contains invalid TE header field value: %q", context, value)
		}
	}
}

func requireValidFuzzTrailer(t *testing.T, h http.Header) {
	t.Helper()
	requireValidFuzzHeader(t, h, "trailer")
	for name := range h {
		require.Truef(t, httpguts.ValidTrailerHeader(name), "trailer contains invalid trailer field name %q", name)
	}
}
