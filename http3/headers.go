package http3

import (
	"bytes"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"

	"github.com/lucas-clemente/quic-go/quicvarint"
	"github.com/marten-seemann/qpack"
	"golang.org/x/net/http/httpguts"
	"golang.org/x/net/idna"
)

// RequestHeaders returns valid HTTP/3 header fields for req, or an error if req
// is malformed.
func RequestHeaders(req *http.Request) ([]qpack.HeaderField, error) {
	host := req.Host
	if host == "" {
		host = req.URL.Host
	}
	host, err := httpguts.PunycodeHostPort(host)
	if err != nil {
		return nil, err
	}

	// FIXME: support extended CONNECT for WebTransport
	var path string
	if req.Method != http.MethodConnect {
		path = req.URL.RequestURI()
		if !validPseudoPath(path) {
			orig := path
			path = strings.TrimPrefix(path, req.URL.Scheme+"://"+host)
			if !validPseudoPath(path) {
				if req.URL.Opaque != "" {
					return nil, fmt.Errorf("invalid request :path %q from URL.Opaque = %q", orig, req.URL.Opaque)
				} else {
					return nil, fmt.Errorf("invalid request :path %q", orig)
				}
			}
		}
	}

	var fields []qpack.HeaderField
	f := func(name, value string) {
		name = strings.ToLower(name)
		fields = append(fields, qpack.HeaderField{Name: name, Value: value})
	}

	// 8.1.2.3 Request Pseudo-Header Fields
	// The :path pseudo-header field includes the path and query parts of the
	// target URI (the path-absolute production and optionally a '?' character
	// followed by the query production (see Sections 3.3 and 3.4 of
	// [RFC3986]).
	f(":authority", host)
	f(":method", req.Method)
	if req.Method != "CONNECT" {
		f(":path", path)
		f(":scheme", req.URL.Scheme)
	}

	var didUA bool
	for k, vv := range req.Header {
		if k == ":protocol" && req.Method == http.MethodConnect {
			// TODO: is this right?
		} else if !httpguts.ValidHeaderFieldName(k) {
			return nil, fmt.Errorf("invalid HTTP header name %q", k)
		}

		if strings.EqualFold(k, "host") || strings.EqualFold(k, "content-length") {
			// Host is :authority, already sent.
			// Content-Length is automatic, set below.
			continue
		} else if strings.EqualFold(k, "connection") || strings.EqualFold(k, "proxy-connection") ||
			strings.EqualFold(k, "transfer-encoding") || strings.EqualFold(k, "upgrade") ||
			strings.EqualFold(k, "keep-alive") {
			// Per 8.1.2.2 Connection-Specific Header
			// Fields, don't send connection-specific
			// fields. We have already checked if any
			// are error-worthy so just ignore the rest.
			continue
		} else if strings.EqualFold(k, "user-agent") {
			// Match Go's http1 behavior: at most one
			// User-Agent. If set to nil or empty string,
			// then omit it. Otherwise if not mentioned,
			// include the default (below).
			didUA = true
			if len(vv) < 1 {
				continue
			}
			vv = vv[:1]
			if vv[0] == "" {
				continue
			}
		} else if strings.EqualFold(k, "trailer") {
			// Trailer is automatic, set below
			continue
		}

		for _, v := range vv {
			if !httpguts.ValidHeaderFieldValue(v) {
				return nil, fmt.Errorf("invalid HTTP header value %q for header %q", v, k)
			}
			f(k, v)
		}
	}

	contentLength := actualContentLength(req)
	if shouldSendReqContentLength(req.Method, contentLength) {
		f("content-length", strconv.FormatInt(contentLength, 10))
	}

	if !didUA {
		f("user-agent", defaultUserAgent)
	}

	if len(req.Trailer) > 0 {
		trailers := make([]string, 0, len(req.Trailer))
		for k := range req.Trailer {
			if httpguts.ValidTrailerHeader(k) {
				trailers = append(trailers, strings.ToLower(k))
			}
		}
		f("trailer", strings.Join(trailers, ", "))
	}

	return fields, nil
}

// Trailers returns HTTP/3 trailer fields for trailer, or nil
// if there are no valid trailers present.
func Trailers(trailer http.Header) []qpack.HeaderField {
	var fields []qpack.HeaderField
	for k, vv := range trailer {
		if !httpguts.ValidTrailerHeader(k) {
			continue
		}
		for _, v := range vv {
			if !httpguts.ValidHeaderFieldValue(v) {
				continue
			}
			fields = append(fields, qpack.HeaderField{Name: strings.ToLower(k), Value: v})
		}
	}
	return fields
}

// appendGzipHeader appends the correct accept-encoding header to fields.
func appendGzipHeader(fields []qpack.HeaderField) []qpack.HeaderField {
	return append(fields, qpack.HeaderField{Name: "accept-encoding", Value: "gzip"})
}

// authorityAddr returns a given authority (a host/IP, or host:port / ip:port)
// and returns a host:port. The port 443 is added if needed.
func authorityAddr(scheme string, authority string) (addr string) {
	host, port, err := net.SplitHostPort(authority)
	if err != nil { // authority didn't have a port
		port = "443"
		if scheme == "http" {
			port = "80"
		}
		host = authority
	}
	if a, err := idna.ToASCII(host); err == nil {
		host = a
	}
	// IPv6 address literal, without a port:
	if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		return host + ":" + port
	}
	return net.JoinHostPort(host, port)
}

// validPseudoPath reports whether v is a valid :path pseudo-header
// value. It must be either:
//
//     *) a non-empty string starting with '/'
//     *) the string '*', for OPTIONS requests.
//
// For now this is only used a quick check for deciding when to clean
// up Opaque URLs before sending requests from the Transport.
// See golang.org/issue/16847
//
// We used to enforce that the path also didn't start with "//", but
// Google's GFE accepts such paths and Chrome sends them, so ignore
// that part of the spec. See golang.org/issue/19103.
func validPseudoPath(v string) bool {
	return (len(v) > 0 && v[0] == '/') || v == "*"
}

// actualContentLength returns a sanitized version of
// req.ContentLength, where 0 actually means zero (not unknown) and -1
// means unknown.
func actualContentLength(req *http.Request) int64 {
	if req.Body == nil {
		return 0
	}
	if req.ContentLength != 0 {
		return req.ContentLength
	}
	return -1
}

// shouldSendReqContentLength reports whether the http2.Transport should send
// a "content-length" request header. This logic is basically a copy of the net/http
// transferWriter.shouldSendContentLength.
// The contentLength is the corrected contentLength (so 0 means actually 0, not unknown).
// -1 means unknown.
func shouldSendReqContentLength(method string, contentLength int64) bool {
	if contentLength > 0 {
		return true
	}
	if contentLength < 0 {
		return false
	}
	// For zero bodies, whether we send a content-length depends on the method.
	// It also kinda doesn't matter for http2 either way, with END_STREAM.
	switch method {
	case "POST", "PUT", "PATCH":
		return true
	default:
		return false
	}
}

// TODO(ydnar): support dynamic QPACK tables
func writeHeadersFrame(w quicvarint.Writer, fields []qpack.HeaderField, max uint64) error {
	var l uint64
	for i := range fields {
		// https://quicwg.org/base-drafts/draft-ietf-quic-qpack.html#name-dynamic-table-size
		l += uint64(len(fields[i].Name) + len(fields[i].Value) + 32)
	}
	if l > max {
		return fmt.Errorf("HEADERS frame too large: %d bytes (max: %d)", l, max)
	}

	buf := &bytes.Buffer{}
	encoder := qpack.NewEncoder(buf)
	for i := range fields {
		encoder.WriteField(fields[i])
	}

	quicvarint.Write(w, uint64(FrameTypeHeaders))
	quicvarint.Write(w, uint64(buf.Len()))
	_, err := w.Write(buf.Bytes())
	return err
}
