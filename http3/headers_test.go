package http3

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/quic-go/qpack"
	"github.com/stretchr/testify/require"
)

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
		{Name: ":path", Value: path},
		{Name: ":authority", Value: "quic-go.net"},
		{Name: ":method", Value: http.MethodGet},
		{Name: "content-length", Value: "42"},
	}
	req, err := requestFromHeaders(headers)
	require.NoError(t, err)
	require.Equal(t, http.MethodGet, req.Method)
	require.Equal(t, path, req.URL.Path)
	require.Equal(t, "", req.URL.Host)
	require.Equal(t, "HTTP/3.0", req.Proto)
	require.Equal(t, 3, req.ProtoMajor)
	require.Zero(t, req.ProtoMinor)
	require.Equal(t, int64(42), req.ContentLength)
	require.Equal(t, 1, len(req.Header))
	require.Equal(t, "42", req.Header.Get("Content-Length"))
	require.Nil(t, req.Body)
	require.Equal(t, "quic-go.net", req.Host)
	require.Equal(t, path, req.RequestURI)
}

func TestRequestHeadersContentLength(t *testing.T) {
	t.Run("no content length", func(t *testing.T) {
		headers := []qpack.HeaderField{
			{Name: ":path", Value: "/"},
			{Name: ":authority", Value: "quic-go.net"},
			{Name: ":method", Value: http.MethodGet},
		}
		req, err := requestFromHeaders(headers)
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
		req, err := requestFromHeaders(headers)
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
			_, err := requestFromHeaders(tc.headers)
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
		name    string
		headers []qpack.HeaderField
		err     string
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
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := requestFromHeaders(tc.headers)
			require.EqualError(t, err, tc.err)
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
	req, err := requestFromHeaders(headers)
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
	req, err := requestFromHeaders(headers)
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
	req, err := requestFromHeaders(headers)
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
			_, err := requestFromHeaders(tc.headers)
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
	req, err := requestFromHeaders(headers)
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
	_, err := requestFromHeaders(headers)
	require.EqualError(t, err, "extended CONNECT: :scheme, :path and :authority must not be empty")
}

func TestResponseHeaderParsing(t *testing.T) {
	headers := []qpack.HeaderField{
		{Name: ":status", Value: "200"},
		{Name: "content-length", Value: "42"},
	}
	rsp := &http.Response{}
	require.NoError(t, updateResponseFromHeaders(rsp, headers))
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
			err := updateResponseFromHeaders(&http.Response{}, tc.headers)
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
			err := updateResponseFromHeaders(&http.Response{}, headers)
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
	require.NoError(t, updateResponseFromHeaders(&rsp, headers))
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
	require.NoError(t, updateResponseFromHeaders(&http.Response{}, headers))
	headers = []qpack.HeaderField{
		{Name: ":status", Value: "404"},
		{Name: "te", Value: "not-trailers"},
	}
	require.EqualError(t,
		updateResponseFromHeaders(&http.Response{}, headers),
		`invalid TE header field value: "not-trailers"`)
}

func TestResponseTrailerParsing(t *testing.T) {
	trailerHdr, err := parseTrailers([]qpack.HeaderField{
		{Name: "content-length", Value: "42"},
	})
	require.NoError(t, err)
	require.Equal(t, "42", trailerHdr.Get("Content-Length"))
}

func TestResponseTrailerParsingValidation(t *testing.T) {
	headers := []qpack.HeaderField{
		{Name: ":status", Value: "200"},
	}
	_, err := parseTrailers(headers)
	require.EqualError(t, err, "http3: received pseudo header in trailer: :status")
}
