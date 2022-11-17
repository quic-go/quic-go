package http3

import (
	"crypto/tls"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/marten-seemann/qpack"
)

func requestFromHeaders(headers []qpack.HeaderField) (*http.Request, error) {
	var path, authority, method, protocol, scheme, contentLengthStr string

	httpHeaders := http.Header{}
	for _, h := range headers {
		switch h.Name {
		case ":path":
			path = h.Value
		case ":method":
			method = h.Value
		case ":authority":
			authority = h.Value
		case ":protocol":
			protocol = h.Value
		case ":scheme":
			scheme = h.Value
		case "content-length":
			contentLengthStr = h.Value
		default:
			if !h.IsPseudo() {
				httpHeaders.Add(h.Name, h.Value)
			}
		}
	}

	// concatenate cookie headers, see https://tools.ietf.org/html/rfc6265#section-5.4
	if len(httpHeaders["Cookie"]) > 0 {
		httpHeaders.Set("Cookie", strings.Join(httpHeaders["Cookie"], "; "))
	}

	isConnect := method == http.MethodConnect
	// Extended CONNECT, see https://datatracker.ietf.org/doc/html/rfc8441#section-4
	isExtendedConnected := isConnect && protocol != ""
	if isExtendedConnected {
		if scheme == "" || path == "" || authority == "" {
			return nil, errors.New("extended CONNECT: :scheme, :path and :authority must not be empty")
		}
	} else if isConnect {
		if path != "" || authority == "" { // normal CONNECT
			return nil, errors.New(":path must be empty and :authority must not be empty")
		}
	} else if len(path) == 0 || len(authority) == 0 || len(method) == 0 {
		return nil, errors.New(":path, :authority and :method must not be empty")
	}

	var u *url.URL
	var requestURI string
	var err error

	if isConnect {
		u = &url.URL{}
		if isExtendedConnected {
			u, err = url.ParseRequestURI(path)
			if err != nil {
				return nil, err
			}
		} else {
			u.Path = path
		}
		u.Scheme = scheme
		u.Host = authority
		requestURI = authority
	} else {
		protocol = "HTTP/3.0"
		u, err = url.ParseRequestURI(path)
		if err != nil {
			return nil, err
		}
		requestURI = path
	}

	var contentLength int64
	if mayHaveBody(method) {
		if len(contentLengthStr) > 0 {
			// parse the Content-Length header as a uint, without the sign bit, so it can be
			// safely packed back into an int64. The header itself is an uint64, but a Content-Length header
			// cannot be negative.
			if cl, err := strconv.ParseUint(contentLengthStr, 10, 63); err != nil {
				return nil, err
			} else {
				contentLength = int64(cl)
			}
		} else {
			// if there is allowed to be a body based on the http method,
			// and there's no content-length header, we set explicitly to -1, which
			// indicates "unknown length"
			contentLength = -1
		}
	}

	return &http.Request{
		Method:        method,
		URL:           u,
		Proto:         protocol,
		ProtoMajor:    3,
		ProtoMinor:    0,
		Header:        httpHeaders,
		Body:          nil,
		ContentLength: contentLength,
		Host:          authority,
		RequestURI:    requestURI,
		TLS:           &tls.ConnectionState{},
	}, nil
}

func hostnameFromRequest(req *http.Request) string {
	if req.URL != nil {
		return req.URL.Host
	}
	return ""
}

func mayHaveBody(method string) bool {
	switch method {
	// HACK: methods which permit sending a body
	// this isn't entirely accurate, but is a tradeoff we're willing to make
	// to attempt to be more correct. It's technically possible to send a GET
	// request with a body, and this is within spec, it's just extremely frowned upon.
	case http.MethodPost, http.MethodPatch, http.MethodDelete, http.MethodPut:
		return true
	}
	return false
}
