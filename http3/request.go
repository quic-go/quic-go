package http3

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"golang.org/x/net/http/httpguts"

	"github.com/quic-go/qpack"
)

func requestFromHeaders(headers []qpack.HeaderField) (*http.Request, error) {
	var path, authority, method, protocol, scheme, contentLengthStr string

	httpHeaders := http.Header{}
	for _, h := range headers {
		// field names need to be lowercase, see section 4.2 of RFC 9114
		if strings.ToLower(h.Name) != h.Name {
			return nil, fmt.Errorf("header field is not lower-case: %s", h.Name)
		}
		if !httpguts.ValidHeaderFieldValue(h.Value) {
			return nil, fmt.Errorf("invalid header field value for %s: %q", h.Name, h.Value)
		}
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
				if !httpguts.ValidHeaderFieldName(h.Name) {
					return nil, fmt.Errorf("invalid header field name: %q", h.Name)
				}
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
	if len(contentLengthStr) > 0 {
		cl, err := strconv.ParseInt(contentLengthStr, 10, 64)
		if err != nil {
			return nil, err
		}
		httpHeaders.Set("Content-Length", contentLengthStr)
		contentLength = cl
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
	}, nil
}

func hostnameFromRequest(req *http.Request) string {
	if req.URL != nil {
		return req.URL.Host
	}
	return ""
}
