package self_test

import (
	"github.com/Noooste/fhttp"
	"io"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/Noooste/quic-go"
	"github.com/Noooste/quic-go/http3"
	"github.com/stretchr/testify/require"
)

func TestHTTP3ServerHotswap(t *testing.T) {
	mux1 := http.NewServeMux()
	mux1.HandleFunc("/hello1", func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "Hello, World 1!\n") // don't check the error here. Stream may be reset.
	})

	mux2 := http.NewServeMux()
	mux2.HandleFunc("/hello2", func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "Hello, World 2!\n") // don't check the error here. Stream may be reset.
	})

	server1 := &http3.Server{
		Handler:    mux1,
		QUICConfig: getQuicConfig(nil),
	}
	server2 := &http3.Server{
		Handler:    mux2,
		QUICConfig: getQuicConfig(nil),
	}

	tlsConf := http3.ConfigureTLSConfig(getTLSConfig())
	ln, err := quic.ListenEarly(newUDPConnLocalhost(t), tlsConf, getQuicConfig(nil))
	require.NoError(t, err)
	port := strconv.Itoa(ln.Addr().(*net.UDPAddr).Port)

	rt := &http3.Transport{
		TLSClientConfig:    getTLSClientConfig(),
		DisableCompression: true,
		QUICConfig:         getQuicConfig(&quic.Config{MaxIdleTimeout: 10 * time.Second}),
	}
	client := &http.Client{Transport: rt}

	defer func() {
		require.NoError(t, rt.Close())
		require.NoError(t, ln.Close())
	}()

	// open first server and make single request to it
	errChan1 := make(chan error, 1)
	go func() { errChan1 <- server1.ServeListener(ln) }()

	resp, err := client.Get("https://localhost:" + port + "/hello1")
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.Equal(t, "Hello, World 1!\n", string(body))

	// open second server with same underlying listener
	errChan2 := make(chan error, 1)
	go func() { errChan2 <- server2.ServeListener(ln) }()

	time.Sleep(scaleDuration(20 * time.Millisecond))
	select {
	case err := <-errChan1:
		t.Fatalf("server1 stopped unexpectedly: %v", err)
	case err := <-errChan2:
		t.Fatalf("server2 stopped unexpectedly: %v", err)
	default:
	}

	// now close first server
	require.NoError(t, server1.Close())
	select {
	case err := <-errChan1:
		require.ErrorIs(t, err, http.ErrServerClosed)
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for server1 to stop")
	}
	require.NoError(t, client.Transport.(*http3.Transport).Close())

	// verify that new connections are handled by the second server now
	resp, err = client.Get("https://localhost:" + port + "/hello2")
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	body, err = io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.Equal(t, "Hello, World 2!\n", string(body))

	// close the other server
	require.NoError(t, server2.Close())
	select {
	case err := <-errChan2:
		require.ErrorIs(t, err, http.ErrServerClosed)
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for server2 to stop")
	}
}
