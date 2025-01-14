package self_test

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/textproto"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	quicproxy "github.com/quic-go/quic-go/integrationtests/tools/proxy"
	"github.com/stretchr/testify/require"
)

type traceEvent struct {
	Key  string
	Args any
}

func newClientTrace(eventQueue chan traceEvent) *httptrace.ClientTrace {
	return &httptrace.ClientTrace{
		GetConn:              func(hostPort string) { eventQueue <- traceEvent{Key: "GetConn", Args: hostPort} },
		GotConn:              func(info httptrace.GotConnInfo) { eventQueue <- traceEvent{Key: "GotConn", Args: info} },
		GotFirstResponseByte: func() { eventQueue <- traceEvent{Key: "GotFirstResponseByte"} },
		Got100Continue:       func() { eventQueue <- traceEvent{Key: "Got100Continue"} },
		Got1xxResponse: func(code int, header textproto.MIMEHeader) error {
			eventQueue <- traceEvent{Key: "Got1xxResponse", Args: code}
			return nil
		},
		DNSStart: func(di httptrace.DNSStartInfo) { eventQueue <- traceEvent{Key: "DNSStart", Args: di} },
		DNSDone:  func(di httptrace.DNSDoneInfo) { eventQueue <- traceEvent{Key: "DNSDone", Args: di} },
		ConnectStart: func(network, addr string) {
			eventQueue <- traceEvent{Key: "ConnectStart", Args: map[string]string{"network": network, "addr": addr}}
		},
		ConnectDone: func(network, addr string, err error) {
			eventQueue <- traceEvent{Key: "ConnectDone", Args: map[string]any{"network": network, "addr": addr, "err": err}}
		},
		TLSHandshakeStart: func() {
			eventQueue <- traceEvent{Key: "TLSHandshakeStart"}
		},
		TLSHandshakeDone: func(state tls.ConnectionState, err error) {
			eventQueue <- traceEvent{Key: "TLSHandshakeDone", Args: map[string]any{"state": state, "err": err}}
		},
		WroteHeaderField: func(key string, value []string) {
			if key != ":authority" {
				return
			}
			eventQueue <- traceEvent{Key: "WroteHeaderField", Args: value[0]}
		},
		WroteHeaders:    func() { eventQueue <- traceEvent{Key: "WroteHeaders"} },
		Wait100Continue: func() { eventQueue <- traceEvent{Key: "Wait100Continue"} },
		WroteRequest:    func(i httptrace.WroteRequestInfo) { eventQueue <- traceEvent{Key: "WroteRequest", Args: i} },
	}
}

func TestHTTPClientTrace(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/client-trace", func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(100 * time.Millisecond)
		w.WriteHeader(http.StatusContinue)
	})
	port := startHTTPServer(t, mux)

	buf := make([]byte, 1)

	eventQueue := make(chan traceEvent, 100)
	trace := newClientTrace(eventQueue)
	ctx := httptrace.WithClientTrace(context.Background(), trace)

	cl := newHTTP3Client(t)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("https://localhost:%d/client-trace", port), nil)
	require.NoError(t, err)
	resp, err := cl.Do(req)
	close(eventQueue)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	events := make([]string, 0, len(eventQueue))
	for e := range eventQueue {
		events = append(events, e.Key)
		switch e.Key {
		case "GetConn":
			require.Equal(t, fmt.Sprintf("localhost:%d", port), e.Args.(string))
		case "GotConn":
			info := e.Args.(httptrace.GotConnInfo)
			require.Equal(t, fmt.Sprintf("127.0.0.1:%d", port), info.Conn.RemoteAddr().String())
			host, _, err := net.SplitHostPort(info.Conn.LocalAddr().String())
			require.NoError(t, err)
			require.Contains(t, []string{"::", "0.0.0.0"}, host)
			require.Panics(t, func() { info.Conn.Close() })
			require.Panics(t, func() { info.Conn.Read(buf) })
			require.Panics(t, func() { info.Conn.Write(buf) })
			require.Panics(t, func() { info.Conn.SetDeadline(time.Now()) })
			require.Panics(t, func() { info.Conn.SetReadDeadline(time.Now()) })
			require.Panics(t, func() { info.Conn.SetWriteDeadline(time.Now()) })
		case "Got1xxResponse":
			require.Equal(t, 100, e.Args.(int))
		case "DNSStart":
			require.Equal(t, "localhost", e.Args.(httptrace.DNSStartInfo).Host)
		case "DNSDone":
			require.Condition(t, func() bool {
				localhost := net.IPv4(127, 0, 0, 1)
				localhostTo16 := localhost.To16()
				for _, addr := range e.Args.(httptrace.DNSDoneInfo).Addrs {
					if addr.IP.Equal(localhost) || addr.IP.Equal(localhostTo16) {
						return true
					}
				}
				return false
			})
		case "ConnectStart":
			require.Equal(t, "udp", e.Args.(map[string]string)["network"])
			require.Equal(t, fmt.Sprintf("127.0.0.1:%d", port), e.Args.(map[string]string)["addr"])
		case "ConnectDone":
			require.Equal(t, "udp", e.Args.(map[string]any)["network"])
			require.Equal(t, fmt.Sprintf("127.0.0.1:%d", port), e.Args.(map[string]any)["addr"])
			require.Nil(t, e.Args.(map[string]any)["err"])
		case "TLSHandshakeDone":
			require.Nil(t, e.Args.(map[string]any)["err"])
			state := e.Args.(map[string]any)["state"].(tls.ConnectionState)
			require.Equal(t, 1, len(state.PeerCertificates))
			require.Equal(t, "localhost", state.PeerCertificates[0].DNSNames[0])
		case "WroteHeaderField":
			require.Equal(t, fmt.Sprintf("localhost:%d", port), e.Args.(string))
		case "WroteRequest":
			require.NoError(t, e.Args.(httptrace.WroteRequestInfo).Err)
		}
	}
	require.Equal(t,
		[]string{
			"GetConn", "DNSStart", "DNSDone", "ConnectStart", "TLSHandshakeStart", "TLSHandshakeDone",
			"ConnectDone", "GotConn", "WroteHeaderField", "WroteHeaders", "WroteRequest",
			"GotFirstResponseByte", "Got1xxResponse", "Got100Continue",
		},
		events,
	)
}

func TestHTTPClientTrace0RTT(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/0rtt", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(strconv.FormatBool(!r.TLS.HandshakeComplete)))
	})
	port := startHTTPServer(t, mux)

	var num0RTTPackets atomic.Uint32
	proxy, err := quicproxy.NewQuicProxy("localhost:0", &quicproxy.Opts{
		RemoteAddr: fmt.Sprintf("localhost:%d", port),
		DelayPacket: func(_ quicproxy.Direction, data []byte) time.Duration {
			if contains0RTTPacket(data) {
				num0RTTPackets.Add(1)
			}
			return scaleDuration(25 * time.Millisecond)
		},
	})
	require.NoError(t, err)
	defer proxy.Close()

	tlsConf := getTLSClientConfigWithoutServerName()
	puts := make(chan string, 10)
	tlsConf.ClientSessionCache = newClientSessionCache(tls.NewLRUClientSessionCache(10), nil, puts)
	tr := &http3.Transport{
		TLSClientConfig:    tlsConf,
		QUICConfig:         getQuicConfig(&quic.Config{MaxIdleTimeout: 10 * time.Second}),
		DisableCompression: true,
	}
	defer tr.Close()

	req, err := http.NewRequest(http3.MethodGet0RTT, fmt.Sprintf("https://localhost:%d/0rtt", proxy.LocalPort()), nil)
	require.NoError(t, err)
	rsp, err := tr.RoundTrip(req)
	require.NoError(t, err)
	require.Equal(t, 200, rsp.StatusCode)
	data, err := io.ReadAll(rsp.Body)
	require.NoError(t, err)
	require.Equal(t, "false", string(data))
	require.Zero(t, num0RTTPackets.Load())

	select {
	case <-puts:
	case <-time.After(time.Second):
		t.Fatal("did not receive session ticket")
	}

	eventQueue := make(chan traceEvent, 100)
	trace := newClientTrace(eventQueue)
	ctx := httptrace.WithClientTrace(context.Background(), trace)
	req = req.WithContext(ctx)

	tr2 := &http3.Transport{
		TLSClientConfig:    tr.TLSClientConfig,
		QUICConfig:         tr.QUICConfig,
		DisableCompression: true,
	}
	defer tr2.Close()
	rsp, err = tr2.RoundTrip(req)
	require.NoError(t, err)
	require.Equal(t, 200, rsp.StatusCode)
	data, err = io.ReadAll(rsp.Body)
	require.NoError(t, err)
	require.Equal(t, "true", string(data))
	require.NotZero(t, num0RTTPackets.Load())
	close(eventQueue)
	events := make([]string, 0, len(eventQueue))
	for e := range eventQueue {
		events = append(events, e.Key)
	}
	require.Equal(t,
		[]string{
			"GetConn", "DNSStart", "DNSDone", "ConnectStart", "TLSHandshakeStart", "ConnectDone",
			"GotConn", "WroteHeaderField", "WroteHeaders", "WroteRequest", "TLSHandshakeDone",
			"GotFirstResponseByte",
		},
		events,
	)
}
