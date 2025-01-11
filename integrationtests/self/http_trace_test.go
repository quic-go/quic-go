package self_test

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/textproto"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	quicproxy "github.com/quic-go/quic-go/integrationtests/tools/proxy"

	"github.com/stretchr/testify/require"
)

func TestHTTPClientTrace(t *testing.T) {
	t.Run("without 0-RTT", func(t *testing.T) {
		testHTTPClientTrace(t, false)
	})

	t.Run("with 0-RTT", func(t *testing.T) {
		testHTTPClientTrace(t, true)
	})
}

func testHTTPClientTrace(t *testing.T, use0RTT bool) {
	mux := http.NewServeMux()
	mux.HandleFunc("/client-trace", func(w http.ResponseWriter, r *http.Request) {
		fmt.Println("handshake complete:", r.TLS.HandshakeComplete)
		w.WriteHeader(http.StatusContinue)
	})
	port := startHTTPServer(t, mux)

	tlsConf := getTLSClientConfigWithoutServerName()
	puts := make(chan string, 10)
	tlsConf.ClientSessionCache = newClientSessionCache(tls.NewLRUClientSessionCache(10), nil, puts)
	tr := &http3.Transport{
		TLSClientConfig:    tlsConf,
		QUICConfig:         getQuicConfig(&quic.Config{MaxIdleTimeout: 10 * time.Second}),
		DisableCompression: true,
	}
	defer tr.Close()

	// when testing 0-RTT, we need to connect first and receive the session ticket
	if use0RTT {
		proxy, err := quicproxy.NewQuicProxy("localhost:0", &quicproxy.Opts{
			RemoteAddr: fmt.Sprintf("localhost:%d", port),
			DelayPacket: func(_ quicproxy.Direction, data []byte) time.Duration {
				return scaleDuration(25 * time.Millisecond)
			},
		})
		require.NoError(t, err)
		defer proxy.Close()
		port = proxy.LocalPort()

		tr2 := &http3.Transport{
			TLSClientConfig:    tr.TLSClientConfig,
			QUICConfig:         tr.QUICConfig,
			DisableCompression: true,
		}
		defer tr2.Close()
		req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("https://localhost:%d", port), nil)
		require.NoError(t, err)
		_, err = tr2.RoundTrip(req)
		require.NoError(t, err)
		select {
		case <-puts:
			fmt.Println("received session ticket")
		case <-time.After(time.Second):
			t.Fatal("didn't receive session ticket")
		}
	}

	buf := make([]byte, 1)
	type event struct {
		Key  string
		Args any
	}
	eventQueue := make(chan event, 100)
	wait100Continue := false
	trace := httptrace.ClientTrace{
		GetConn:              func(hostPort string) { eventQueue <- event{Key: "GetConn", Args: hostPort} },
		GotConn:              func(info httptrace.GotConnInfo) { eventQueue <- event{Key: "GotConn", Args: info} },
		GotFirstResponseByte: func() { eventQueue <- event{Key: "GotFirstResponseByte"} },
		Got100Continue:       func() { eventQueue <- event{Key: "Got100Continue"} },
		Got1xxResponse: func(code int, header textproto.MIMEHeader) error {
			eventQueue <- event{Key: "Got1xxResponse", Args: code}
			return nil
		},
		DNSStart: func(di httptrace.DNSStartInfo) { eventQueue <- event{Key: "DNSStart", Args: di} },
		DNSDone:  func(di httptrace.DNSDoneInfo) { eventQueue <- event{Key: "DNSDone", Args: di} },
		ConnectStart: func(network, addr string) {
			eventQueue <- event{Key: "ConnectStart", Args: map[string]string{"network": network, "addr": addr}}
		},
		ConnectDone: func(network, addr string, err error) {
			eventQueue <- event{Key: "ConnectDone", Args: map[string]any{"network": network, "addr": addr, "err": err}}
		},
		TLSHandshakeStart: func() { eventQueue <- event{Key: "TLSHandshakeStart"} },
		TLSHandshakeDone: func(state tls.ConnectionState, err error) {
			eventQueue <- event{Key: "TLSHandshakeDone", Args: map[string]any{"state": state, "err": err}}
		},
		WroteHeaderField: func(key string, value []string) {
			if key == ":authority" {
				eventQueue <- event{Key: "WroteHeaderField", Args: value[0]}
			}
		},
		WroteHeaders:    func() { eventQueue <- event{Key: "WroteHeaders"} },
		Wait100Continue: func() { wait100Continue = true },
		WroteRequest:    func(i httptrace.WroteRequestInfo) { eventQueue <- event{Key: "WroteRequest", Args: i} },
	}

	cl := http.Client{Transport: tr}
	method := http.MethodGet
	if use0RTT {
		method = http3.MethodGet0RTT
	}
	req, err := http.NewRequestWithContext(
		httptrace.WithClientTrace(context.Background(), &trace),
		method,
		fmt.Sprintf("https://localhost:%d/client-trace", port),
		http.NoBody,
	)
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
			// We can't assert on 0-RTT here, since crypto/tls doesn't expose this on the ConnectionState.
			// We can assert on handshake completion and resumption state.
			if use0RTT {
				require.False(t, state.HandshakeComplete)
				require.True(t, state.DidResume)
			} else {
				require.True(t, state.HandshakeComplete)
				require.False(t, state.DidResume)
			}
		case "WroteHeaderField":
			require.Equal(t, fmt.Sprintf("localhost:%d", port), e.Args.(string))
		case "WroteRequest":
			require.NoError(t, e.Args.(httptrace.WroteRequestInfo).Err)
		}
	}

	require.Falsef(t, wait100Continue, "wait 100 continue") // Note: not supported Expect: 100-continue
	switch use0RTT {
	case true:
		require.Equal(t,
			[]string{
				"GetConn",
				"DNSStart",
				"DNSDone",
				"ConnectStart",
				"TLSHandshakeStart",
				"ConnectDone",
				"GotConn",
				"WroteHeaderField",
				"WroteHeaders",
				"WroteRequest",
				"TLSHandshakeDone",
				"GotFirstResponseByte",
				"Got1xxResponse",
				"Got100Continue",
			},
			events,
		)
	case false:
		require.Equal(t,
			[]string{
				"GetConn",
				"DNSStart",
				"DNSDone",
				"ConnectStart",
				"TLSHandshakeStart",
				"GotConn",
				"TLSHandshakeDone",
				"ConnectDone",
				"WroteHeaderField",
				"WroteHeaders",
				"WroteRequest",
				"GotFirstResponseByte",
				"Got1xxResponse",
				"Got100Continue",
			},
			events,
		)
	}
}
