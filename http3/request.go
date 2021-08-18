package http3

import (
	"context"
	"crypto/tls"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/marten-seemann/qpack"
)

// ProtocolContextKey is the value of the :protocol header, if present.
var ProtocolContextKey = &contextKey{"protocol"}

func requestFromHeaders(ctx context.Context, headers []qpack.HeaderField) (*http.Request, error) {
	var method, authority, path, protocol, contentLengthStr string
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
		case "content-length":
			contentLengthStr = h.Value
		default:
			if !h.IsPseudo() {
				httpHeaders.Add(h.Name, h.Value)
			}
		}
	}

	if protocol != "" {
		ctx = context.WithValue(ctx, ServerContextKey, protocol)
	}

	// concatenate cookie headers, see https://tools.ietf.org/html/rfc6265#section-5.4
	if len(httpHeaders["Cookie"]) > 0 {
		httpHeaders.Set("Cookie", strings.Join(httpHeaders["Cookie"], "; "))
	}

	isConnect := method == http.MethodConnect
	isExtendedConnect := isConnect && protocol != ""
	if isConnect && !isExtendedConnect {
		if path != "" || authority == "" {
			return nil, errors.New(":path must be empty and :authority must not be empty")
		}
	} else if len(path) == 0 || len(authority) == 0 || len(method) == 0 {
		return nil, errors.New(":path, :authority and :method must not be empty")
	}

	var u *url.URL
	var requestURI string
	var err error

	if isConnect && !isExtendedConnect {
		u = &url.URL{Host: authority}
		requestURI = authority
	} else {
		u, err = url.ParseRequestURI(path)
		if err != nil {
			return nil, err
		}
		requestURI = path
	}

	var contentLength int64
	if len(contentLengthStr) > 0 {
		contentLength, err = strconv.ParseInt(contentLengthStr, 10, 64)
		if err != nil {
			return nil, err
		}
	}

	req := &http.Request{
		Method:        method,
		URL:           u,
		Proto:         "HTTP/3",
		ProtoMajor:    3,
		ProtoMinor:    0,
		Header:        httpHeaders,
		Body:          nil,
		ContentLength: contentLength,
		Host:          authority,
		RequestURI:    requestURI,
		TLS:           &tls.ConnectionState{},
	}

	return req.WithContext(ctx), nil
}

func hostnameFromRequest(req *http.Request) string {
	if req.URL != nil {
		return req.URL.Host
	}
	return ""
}
