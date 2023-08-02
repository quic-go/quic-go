package http3

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"

	"github.com/quic-go/quic-go"
	tls "github.com/refraction-networking/utls"
	"golang.org/x/net/http/httpguts"
)

type URoundTripper struct {
	*RoundTripper

	quicSpec           *quic.QUICSpec
	uTransportOverride *quic.UTransport
}

func GetURoundTripper(r *RoundTripper, QUICSpec *quic.QUICSpec, uTransport *quic.UTransport) *URoundTripper {
	QUICSpec.UpdateConfig(r.QuicConfig)

	return &URoundTripper{
		RoundTripper:       r,
		quicSpec:           QUICSpec,
		uTransportOverride: uTransport,
	}
}

// RoundTripOpt is like RoundTrip, but takes options.
func (r *URoundTripper) RoundTripOpt(req *http.Request, opt RoundTripOpt) (*http.Response, error) {
	if req.URL == nil {
		closeRequestBody(req)
		return nil, errors.New("http3: nil Request.URL")
	}
	if req.URL.Scheme != "https" {
		closeRequestBody(req)
		return nil, fmt.Errorf("http3: unsupported protocol scheme: %s", req.URL.Scheme)
	}
	if req.URL.Host == "" {
		closeRequestBody(req)
		return nil, errors.New("http3: no Host in request URL")
	}
	if req.Header == nil {
		closeRequestBody(req)
		return nil, errors.New("http3: nil Request.Header")
	}
	for k, vv := range req.Header {
		if !httpguts.ValidHeaderFieldName(k) {
			return nil, fmt.Errorf("http3: invalid http header field name %q", k)
		}
		for _, v := range vv {
			if !httpguts.ValidHeaderFieldValue(v) {
				return nil, fmt.Errorf("http3: invalid http header field value %q for key %v", v, k)
			}
		}
	}

	if req.Method != "" && !validMethod(req.Method) {
		closeRequestBody(req)
		return nil, fmt.Errorf("http3: invalid method %q", req.Method)
	}

	hostname := authorityAddr("https", hostnameFromRequest(req))
	cl, isReused, err := r.getClient(hostname, opt.OnlyCachedConn)
	if err != nil {
		return nil, err
	}
	defer cl.useCount.Add(-1)
	rsp, err := cl.RoundTripOpt(req, opt)
	if err != nil {
		r.removeClient(hostname)
		if isReused {
			if nerr, ok := err.(net.Error); ok && nerr.Timeout() {
				return r.RoundTripOpt(req, opt)
			}
		}
	}
	return rsp, err
}

// RoundTrip does a round trip.
func (r *URoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	return r.RoundTripOpt(req, RoundTripOpt{})
}

func (r *URoundTripper) getClient(hostname string, onlyCached bool) (rtc *roundTripCloserWithCount, isReused bool, err error) {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	if r.clients == nil {
		r.clients = make(map[string]*roundTripCloserWithCount)
	}

	client, ok := r.clients[hostname]
	if !ok {
		if onlyCached {
			return nil, false, ErrNoCachedConn
		}
		var err error
		newCl := newClient
		if r.newClient != nil {
			newCl = r.newClient
		}
		dial := r.Dial
		if dial == nil {
			if r.transport == nil && r.uTransportOverride == nil {
				udpConn, err := net.ListenUDP("udp", nil)
				if err != nil {
					return nil, false, err
				}
				r.uTransportOverride = &quic.UTransport{
					Transport: &quic.Transport{
						Conn: udpConn,
					},
					QUICSpec: r.quicSpec,
				}
			}
			dial = r.makeDialer()
		}
		c, err := newCl(
			hostname,
			r.TLSClientConfig,
			&roundTripperOpts{
				EnableDatagram:     r.EnableDatagrams,
				DisableCompression: r.DisableCompression,
				MaxHeaderBytes:     r.MaxResponseHeaderBytes,
				StreamHijacker:     r.StreamHijacker,
				UniStreamHijacker:  r.UniStreamHijacker,
			},
			r.QuicConfig,
			dial,
		)
		if err != nil {
			return nil, false, err
		}
		client = &roundTripCloserWithCount{roundTripCloser: c}
		r.clients[hostname] = client
	} else if client.HandshakeComplete() {
		isReused = true
	}
	client.useCount.Add(1)
	return client, isReused, nil
}

func (r *URoundTripper) Close() error {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	for _, client := range r.clients {
		if err := client.Close(); err != nil {
			return err
		}
	}
	r.clients = nil
	if r.transport != nil {
		if err := r.transport.Close(); err != nil {
			return err
		}
		if err := r.transport.Conn.Close(); err != nil {
			return err
		}
		r.transport = nil
	}
	if r.uTransportOverride != nil {
		if err := r.uTransportOverride.Close(); err != nil {
			return err
		}
		if err := r.uTransportOverride.Conn.Close(); err != nil {
			return err
		}
		r.uTransportOverride = nil
	}
	return nil
}

// makeDialer makes a QUIC dialer using r.udpConn.
func (r *URoundTripper) makeDialer() func(ctx context.Context, addr string, tlsCfg *tls.Config, cfg *quic.Config) (quic.EarlyConnection, error) {
	return func(ctx context.Context, addr string, tlsCfg *tls.Config, cfg *quic.Config) (quic.EarlyConnection, error) {
		udpAddr, err := net.ResolveUDPAddr("udp", addr)
		if err != nil {
			return nil, err
		}
		if r.uTransportOverride != nil {
			return r.uTransportOverride.DialEarly(ctx, udpAddr, tlsCfg, cfg)
		} else if r.transport == nil {
			return nil, errors.New("http3: no QUIC transport available")
		}
		return r.transport.DialEarly(ctx, udpAddr, tlsCfg, cfg)
	}
}
