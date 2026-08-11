package self_test

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	quicproxy "github.com/quic-go/quic-go/integrationtests/tools/proxy"
	"github.com/quic-go/quic-go/internal/protocol"

	"github.com/stretchr/testify/require"
)

func TestHTTP0RTT(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/0rtt", func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, strconv.FormatBool(!r.TLS.HandshakeComplete))
	})
	port := startHTTPServer(t, mux)

	var num0RTTPackets atomic.Uint32
	proxy := quicproxy.Proxy{
		Conn:       newUDPConnLocalhost(t),
		ServerAddr: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port},
		DelayPacket: func(_ quicproxy.Direction, _, _ net.Addr, data []byte) time.Duration {
			if containsPacketType(data, protocol.PacketType0RTT) {
				num0RTTPackets.Add(1)
			}
			return scaleDuration(25 * time.Millisecond)
		},
	}
	require.NoError(t, proxy.Start())
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
	addDialCallback(t, tr)

	proxyPort := proxy.LocalAddr().(*net.UDPAddr).Port
	req, err := http.NewRequest(http3.MethodGet0RTT, fmt.Sprintf("https://localhost:%d/0rtt", proxyPort), nil)
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

	tr2 := &http3.Transport{
		TLSClientConfig:    tr.TLSClientConfig,
		QUICConfig:         tr.QUICConfig,
		DisableCompression: true,
	}
	defer tr2.Close()
	addDialCallback(t, tr2)
	rsp, err = tr2.RoundTrip(req)
	require.NoError(t, err)
	require.Equal(t, 200, rsp.StatusCode)
	data, err = io.ReadAll(rsp.Body)
	require.NoError(t, err)
	require.Equal(t, "true", string(data))
	require.NotZero(t, num0RTTPackets.Load())
}

// TestHTTP0RTTIncompatibleServerSettings tests the client side of RFC 9114, section 7.2.4.2:
// if a server accepts 0-RTT, but then sends a SETTINGS frame that is incompatible with the
// settings the client used for its 0-RTT data, the client closes the connection
// with H3_SETTINGS_ERROR.
func TestHTTP0RTTIncompatibleServerSettings(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/0rtt", func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, strconv.FormatBool(!r.TLS.HandshakeComplete))
	})

	// Set up the listener manually, using the exported ConfigureTLSConfig. That way the server
	// doesn't store its settings in the session ticket, and therefore doesn't reject 0-RTT when
	// its own settings change - which is exactly the misbehavior the client needs to catch.
	serverTLSConf := getTLSConfig()
	startServer := func(t *testing.T, maxHeaderBytes int) int {
		t.Helper()

		ln, err := quic.ListenEarly(
			newUDPConnLocalhost(t),
			http3.ConfigureTLSConfig(serverTLSConf),
			getQuicConfig(&quic.Config{Allow0RTT: true}),
		)
		require.NoError(t, err)
		server := &http3.Server{Handler: mux, MaxHeaderBytes: maxHeaderBytes}
		go server.ServeListener(ln)
		t.Cleanup(func() { server.Close() })
		return ln.Addr().(*net.UDPAddr).Port
	}

	puts := make(chan string, 1)
	clientTLSConf := getTLSClientConfigWithoutServerName()
	clientTLSConf.ClientSessionCache = newClientSessionCache(tls.NewLRUClientSessionCache(1), nil, puts)
	// doRequest returns the QUIC connection that the request was sent on,
	// so that the test can tell how the connection was closed.
	doRequest := func(port int) (*quic.Conn, string, error) {
		var mx sync.Mutex
		var conn *quic.Conn
		tr := &http3.Transport{
			TLSClientConfig:    clientTLSConf,
			QUICConfig:         getQuicConfig(&quic.Config{MaxIdleTimeout: 10 * time.Second}),
			DisableCompression: true,
			Dial: func(ctx context.Context, addr string, tlsConf *tls.Config, quicConf *quic.Config) (*quic.Conn, error) {
				udpAddr, err := net.ResolveUDPAddr("udp", addr)
				if err != nil {
					return nil, err
				}
				c, err := quic.DialEarly(ctx, newUDPConnLocalhost(t), udpAddr, tlsConf, quicConf)
				if err != nil {
					return nil, err
				}
				mx.Lock()
				conn = c
				mx.Unlock()
				return c, nil
			},
		}
		t.Cleanup(func() { tr.Close() })

		req, err := http.NewRequest(http3.MethodGet0RTT, fmt.Sprintf("https://localhost:%d/0rtt", port), nil)
		require.NoError(t, err)
		rsp, err := tr.RoundTrip(req)
		mx.Lock()
		defer mx.Unlock()
		if err != nil {
			return conn, "", err
		}
		defer rsp.Body.Close()
		body, err := io.ReadAll(rsp.Body)
		return conn, string(body), err
	}

	_, body, err := doRequest(startServer(t, 1024))
	require.NoError(t, err)
	require.Equal(t, "false", body)
	select {
	case <-puts:
	case <-time.After(time.Second):
		t.Fatal("did not receive session ticket")
	}

	// This server accepts the 0-RTT data, but then announces a smaller maximum field section size.
	proxy := quicproxy.Proxy{
		Conn:       newUDPConnLocalhost(t),
		ServerAddr: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: startServer(t, 1023)},
		DelayPacket: func(quicproxy.Direction, net.Addr, net.Addr, []byte) time.Duration {
			return scaleDuration(25 * time.Millisecond)
		},
	}
	require.NoError(t, proxy.Start())
	defer proxy.Close()

	// The SETTINGS frame is processed asynchronously, so the 0-RTT request itself may still
	// succeed. What matters is that the connection is torn down with H3_SETTINGS_ERROR.
	conn, _, _ := doRequest(proxy.LocalAddr().(*net.UDPAddr).Port)
	require.NotNil(t, conn)
	select {
	case <-conn.Context().Done():
	case <-time.After(time.Second):
		t.Fatal("connection was not closed")
	}
	var appErr *quic.ApplicationError
	require.ErrorAs(t, context.Cause(conn.Context()), &appErr)
	require.False(t, appErr.Remote)
	require.Equal(t, quic.ApplicationErrorCode(http3.ErrCodeSettingsError), appErr.ErrorCode)
}

func TestHTTP0RTTWithChangedServerSettings(t *testing.T) {
	const originalMaxHeaderBytes = 1024

	for _, tc := range []struct {
		name              string
		newMaxHeaderBytes int
		expect0RTT        bool
	}{
		{name: "increased", newMaxHeaderBytes: 1025, expect0RTT: true},
		{name: "decreased", newMaxHeaderBytes: 1023, expect0RTT: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mux := http.NewServeMux()
			mux.HandleFunc("/0rtt", func(w http.ResponseWriter, r *http.Request) {
				io.WriteString(w, strconv.FormatBool(!r.TLS.HandshakeComplete))
			})
			serverTLSConf := getTLSConfig()
			port := startHTTPServer(t, mux, func(s *http3.Server) {
				s.TLSConfig = serverTLSConf
				s.MaxHeaderBytes = originalMaxHeaderBytes
			})

			puts := make(chan string, 1)
			clientTLSConf := getTLSClientConfigWithoutServerName()
			clientTLSConf.ClientSessionCache = newClientSessionCache(tls.NewLRUClientSessionCache(1), nil, puts)
			doRequest := func(port int) (string, error) {
				cl := newHTTP3Client(t, func(tr *http3.Transport) { tr.TLSClientConfig = clientTLSConf })
				req, err := http.NewRequest(http3.MethodGet0RTT, fmt.Sprintf("https://localhost:%d/0rtt", port), nil)
				require.NoError(t, err)
				rsp, err := cl.Do(req)
				if err != nil {
					return "", err
				}
				defer rsp.Body.Close()
				body, err := io.ReadAll(rsp.Body)
				return string(body), err
			}

			body, err := doRequest(port)
			require.NoError(t, err)
			require.Equal(t, "false", body)
			select {
			case <-puts:
			case <-time.After(time.Second):
				t.Fatal("did not receive session ticket")
			}

			port = startHTTPServer(t, mux, func(s *http3.Server) {
				s.TLSConfig = serverTLSConf
				s.MaxHeaderBytes = tc.newMaxHeaderBytes
			})
			proxy := quicproxy.Proxy{
				Conn:       newUDPConnLocalhost(t),
				ServerAddr: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port},
				DelayPacket: func(quicproxy.Direction, net.Addr, net.Addr, []byte) time.Duration {
					return scaleDuration(25 * time.Millisecond)
				},
			}
			require.NoError(t, proxy.Start())
			defer proxy.Close()

			proxyPort := proxy.LocalAddr().(*net.UDPAddr).Port
			body, err = doRequest(proxyPort)
			if tc.expect0RTT {
				require.NoError(t, err)
				require.Equal(t, "true", body)
			} else {
				require.ErrorIs(t, err, quic.Err0RTTRejected)
			}
		})
	}
}
