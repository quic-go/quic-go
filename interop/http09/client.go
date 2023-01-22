package http09

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"

	"golang.org/x/net/idna"

	"github.com/quic-go/quic-go"
)

// MethodGet0RTT allows a GET request to be sent using 0-RTT.
// Note that 0-RTT data doesn't provide replay protection.
const MethodGet0RTT = "GET_0RTT"

// RoundTripper performs HTTP/0.9 roundtrips over QUIC.
type RoundTripper struct {
	mutex sync.Mutex

	TLSClientConfig *tls.Config
	QuicConfig      *quic.Config

	clients map[string]*client
}

var _ http.RoundTripper = &RoundTripper{}

// RoundTrip performs a HTTP/0.9 request.
// It only supports GET requests.
func (r *RoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.Method != http.MethodGet && req.Method != MethodGet0RTT {
		return nil, errors.New("only GET requests supported")
	}

	log.Printf("Requesting %s.\n", req.URL)

	r.mutex.Lock()
	hostname := authorityAddr("https", hostnameFromRequest(req))
	if r.clients == nil {
		r.clients = make(map[string]*client)
	}
	c, ok := r.clients[hostname]
	if !ok {
		tlsConf := &tls.Config{}
		if r.TLSClientConfig != nil {
			tlsConf = r.TLSClientConfig.Clone()
		}
		tlsConf.NextProtos = []string{h09alpn}
		c = &client{
			hostname: hostname,
			tlsConf:  tlsConf,
			quicConf: r.QuicConfig,
		}
		r.clients[hostname] = c
	}
	r.mutex.Unlock()
	return c.RoundTrip(req)
}

// Close closes the roundtripper.
func (r *RoundTripper) Close() error {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	for id, c := range r.clients {
		if err := c.Close(); err != nil {
			return err
		}
		delete(r.clients, id)
	}
	return nil
}

type client struct {
	hostname string
	tlsConf  *tls.Config
	quicConf *quic.Config

	once    sync.Once
	conn    quic.EarlyConnection
	dialErr error
}

func (c *client) RoundTrip(req *http.Request) (*http.Response, error) {
	c.once.Do(func() {
		c.conn, c.dialErr = quic.DialAddrEarly(c.hostname, c.tlsConf, c.quicConf)
	})
	if c.dialErr != nil {
		return nil, c.dialErr
	}
	if req.Method != MethodGet0RTT {
		<-c.conn.HandshakeComplete().Done()
	}
	return c.doRequest(req)
}

func (c *client) doRequest(req *http.Request) (*http.Response, error) {
	str, err := c.conn.OpenStreamSync(context.Background())
	if err != nil {
		return nil, err
	}
	cmd := "GET " + req.URL.Path + "\r\n"
	if _, err := str.Write([]byte(cmd)); err != nil {
		return nil, err
	}
	if err := str.Close(); err != nil {
		return nil, err
	}
	rsp := &http.Response{
		Proto:      "HTTP/0.9",
		ProtoMajor: 0,
		ProtoMinor: 9,
		Request:    req,
		Body:       io.NopCloser(str),
	}
	return rsp, nil
}

func (c *client) Close() error {
	if c.conn == nil {
		return nil
	}
	return c.conn.CloseWithError(0, "")
}

func hostnameFromRequest(req *http.Request) string {
	if req.URL != nil {
		return req.URL.Host
	}
	return ""
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
