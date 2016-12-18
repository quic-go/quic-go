package h2quic

import (
	"net/http"
	"sync"
)

type h2quicClient interface {
	Do(*http.Request) (*http.Response, error)
}

// QuicRoundTripper implements the http.RoundTripper interface
type QuicRoundTripper struct {
	mutex sync.Mutex

	clients map[string]h2quicClient
}

var _ http.RoundTripper = &QuicRoundTripper{}

// RoundTrip does a round trip
func (r *QuicRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
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
		client, err = NewClient(hostname)
		if err != nil {
			return nil, err
		}
		r.clients[hostname] = client
	}
	return client, nil
}
