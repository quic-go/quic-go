package self_test

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
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
