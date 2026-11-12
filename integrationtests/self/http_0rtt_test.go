package self_test

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/testutils/simnet"

	"github.com/stretchr/testify/require"
)

func TestHTTP0RTT(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var num0RTTPackets atomic.Uint32
		n := newTestNetworkWithSettings(t, simnet.NodeBiDiLinkSettings{
			LatencyFunc: func(p simnet.Packet) time.Duration {
				if containsPacketType(p.Data, protocol.PacketType0RTT) {
					num0RTTPackets.Add(1)
				}
				return 25 * time.Millisecond
			},
		})
		mux := http.NewServeMux()
		mux.HandleFunc("/0rtt", func(w http.ResponseWriter, r *http.Request) {
			io.WriteString(w, strconv.FormatBool(!r.TLS.HandshakeComplete))
		})
		port := startHTTPServer(t, n.NewConn(), mux)

		tlsConf := getTLSClientConfigWithoutServerName()
		puts := make(chan string, 10)
		tlsConf.ClientSessionCache = newClientSessionCache(tls.NewLRUClientSessionCache(10), nil, puts)
		tr := &http3.Transport{
			TLSClientConfig:    tlsConf,
			QUICConfig:         getQuicConfig(&quic.Config{MaxIdleTimeout: 10 * time.Second}),
			DisableCompression: true,
			Dial:               n.DialEarly,
		}
		defer tr.Close()

		req, err := http.NewRequest(http3.MethodGet0RTT, fmt.Sprintf("https://localhost:%d/0rtt", port), nil)
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
			Dial:               n.DialEarly,
		}
		defer tr2.Close()
		rsp, err = tr2.RoundTrip(req)
		require.NoError(t, err)
		require.Equal(t, 200, rsp.StatusCode)
		data, err = io.ReadAll(rsp.Body)
		require.NoError(t, err)
		require.Equal(t, "true", string(data))
		require.NotZero(t, num0RTTPackets.Load())
	})
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
			synctest.Test(t, func(t *testing.T) {
				n := newTestNetworkWithSettings(t, simnet.NodeBiDiLinkSettings{Latency: 25 * time.Millisecond})
				mux := http.NewServeMux()
				mux.HandleFunc("/0rtt", func(w http.ResponseWriter, r *http.Request) {
					io.WriteString(w, strconv.FormatBool(!r.TLS.HandshakeComplete))
				})
				serverTLSConf := getTLSConfig()
				port := startHTTPServer(t, n.NewConn(), mux, func(s *http3.Server) {
					s.TLSConfig = serverTLSConf
					s.MaxHeaderBytes = originalMaxHeaderBytes
				})

				puts := make(chan string, 1)
				clientTLSConf := getTLSClientConfigWithoutServerName()
				clientTLSConf.ClientSessionCache = newClientSessionCache(tls.NewLRUClientSessionCache(1), nil, puts)
				doRequest := func(port int) (string, error) {
					cl := newHTTP3Client(t, n, func(tr *http3.Transport) { tr.TLSClientConfig = clientTLSConf })
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

				port = startHTTPServer(t, n.NewConn(), mux, func(s *http3.Server) {
					s.TLSConfig = serverTLSConf
					s.MaxHeaderBytes = tc.newMaxHeaderBytes
				})
				body, err = doRequest(port)
				if tc.expect0RTT {
					require.NoError(t, err)
					require.Equal(t, "true", body)
				} else {
					require.ErrorIs(t, err, quic.Err0RTTRejected)
				}
			})
		})
	}
}

func TestHTTP0RTTRejectsIncompatibleServerSettings(t *testing.T) {
	const originalMaxHeaderBytes = 1024

	// Establish a session and cache the server's original SETTINGS.
	serverTLSConf := getTLSConfig()
	port := startHTTPServer(t, http.NewServeMux(), func(s *http3.Server) {
		s.TLSConfig = serverTLSConf
		s.MaxHeaderBytes = originalMaxHeaderBytes
	})

	puts := make(chan string, 1)
	clientTLSConf := getTLSClientConfigWithoutServerName()
	clientTLSConf.ClientSessionCache = newClientSessionCache(tls.NewLRUClientSessionCache(1), nil, puts)
	client := newHTTP3Client(t, func(tr *http3.Transport) { tr.TLSClientConfig = clientTLSConf })
	rsp, err := client.Get(fmt.Sprintf("https://localhost:%d/", port))
	require.NoError(t, err)
	require.NoError(t, rsp.Body.Close())
	select {
	case <-puts:
	case <-time.After(time.Second):
		t.Fatal("did not receive session ticket")
	}

	// Deliberately bypass the HTTP/3 server's 0-RTT SETTINGS compatibility check.
	ln, err := quic.ListenEarly(
		newUDPConnLocalhost(t),
		http3.ConfigureTLSConfig(serverTLSConf),
		getQuicConfig(&quic.Config{Allow0RTT: true, EnableDatagrams: true}),
	)
	require.NoError(t, err)
	defer ln.Close()

	resultChan := make(chan error, 1)
	go func() {
		conn, err := ln.Accept(t.Context())
		if err != nil {
			resultChan <- err
			return
		}
		defer conn.CloseWithError(0, "")
		// Send reduced SETTINGS after accepting 0-RTT, simulating a misbehaving HTTP/3 server.
		if _, err := (&http3.Server{MaxHeaderBytes: originalMaxHeaderBytes - 1}).NewRawServerConn(conn); err != nil {
			resultChan <- err
			return
		}
		<-conn.Context().Done()
		resultChan <- context.Cause(conn.Context())
	}()

	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	client = newHTTP3Client(t, func(tr *http3.Transport) { tr.TLSClientConfig = clientTLSConf })
	req, err := http.NewRequestWithContext(ctx, http3.MethodGet0RTT, fmt.Sprintf("https://localhost:%d/", ln.Addr().(*net.UDPAddr).Port), nil)
	require.NoError(t, err)
	_, err = client.Do(req)
	require.Error(t, err)

	var serverErr error
	select {
	case serverErr = <-resultChan:
	case <-ctx.Done():
		t.Fatal("timeout waiting for connection close")
	}
	require.ErrorIs(t, serverErr, &quic.ApplicationError{
		Remote:    true,
		ErrorCode: quic.ApplicationErrorCode(http3.ErrCodeSettingsError),
	})
	require.ErrorContains(t, serverErr, "server sent incompatible settings after accepting 0-RTT")
}
