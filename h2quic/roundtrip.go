package h2quic

import (
	"errors"
	"net/http"
	"sync"
)

type h2quicClient interface {
	Do(*http.Request) (*http.Response, error)
}

// QuicRoundTripper implements the http.RoundTripper interface
type QuicRoundTripper struct {
	mutex sync.Mutex

	// DisableCompression, if true, prevents the Transport from
	// requesting compression with an "Accept-Encoding: gzip"
	// request header when the Request contains no existing
	// Accept-Encoding value. If the Transport requests gzip on
	// its own and gets a gzipped response, it's transparently
	// decoded in the Response.Body. However, if the user
	// explicitly requested gzip it is not automatically
	// uncompressed.
	DisableCompression bool

	clients map[string]h2quicClient
}

var _ http.RoundTripper = &QuicRoundTripper{}

// RoundTrip does a round trip
func (r *QuicRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL == nil {
		closeRequestBody(req)
		return nil, errors.New("quic: nil Request.URL")
	}
	if req.URL.Host == "" {
		closeRequestBody(req)
		return nil, errors.New("quic: no Host in request URL")
	}
	if req.Header == nil {
		closeRequestBody(req)
		return nil, errors.New("quic: nil Request.Header")
	}

	hostname := authorityAddr("https", hostnameFromRequest(req))
	client, err := r.getClient(hostname)
	if err != nil {
		return nil, err
	}
	return client.Do(req)
}

func (r *QuicRoundTripper) getClient(hostname string) (h2quicClient, error) {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	if r.clients == nil {
		r.clients = make(map[string]h2quicClient)
	}

	client, ok := r.clients[hostname]
	if !ok {
		var err error
		client, err = NewClient(r, hostname)
		if err != nil {
			return nil, err
		}
		r.clients[hostname] = client
	}
	return client, nil
}

func (r *QuicRoundTripper) disableCompression() bool {
	return r.DisableCompression
}

func closeRequestBody(req *http.Request) {
	if req.Body != nil {
		req.Body.Close()
	}
}
