package http09

import (
	"fmt"
	"github.com/Noooste/fhttp"
	"github.com/Noooste/utls"
	"io"
	"net"
	"net/http/httptest"
	"testing"

	"github.com/Noooste/uquic-go"
	"github.com/Noooste/uquic-go/internal/testdata"

	"github.com/stretchr/testify/require"
)

func startServer(t *testing.T) net.Addr {
	t.Helper()
	server := &Server{}
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	require.NoError(t, err)
	tr := &quic.Transport{Conn: conn}
	tlsConf := testdata.GetTLSConfig()
	tlsConf.NextProtos = []string{NextProto}
	ln, err := tr.ListenEarly(tlsConf, &quic.Config{})
	require.NoError(t, err)
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = server.ServeListener(ln)
	}()
	t.Cleanup(func() {
		require.NoError(t, ln.Close())
		<-done
	})
	return ln.Addr()
}

func TestHTTPRequest(t *testing.T) {
	http.HandleFunc("/helloworld", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("Hello World!"))
	})

	addr := startServer(t)

	rt := &RoundTripper{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	t.Cleanup(func() { rt.Close() })

	req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("https://%s/helloworld", addr), nil)
	rsp, err := rt.RoundTrip(req)
	require.NoError(t, err)
	data, err := io.ReadAll(rsp.Body)
	require.NoError(t, err)
	require.Equal(t, []byte("Hello World!"), data)
}

func TestHTTPHeaders(t *testing.T) {
	http.HandleFunc("/headers", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("foo", "bar")
		w.WriteHeader(1337)
		_, _ = w.Write([]byte("done"))
	})

	addr := startServer(t)

	rt := &RoundTripper{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	t.Cleanup(func() { rt.Close() })

	req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("https://%s/headers", addr), nil)
	rsp, err := rt.RoundTrip(req)
	require.NoError(t, err)
	data, err := io.ReadAll(rsp.Body)
	require.NoError(t, err)
	require.Equal(t, []byte("done"), data)
	// HTTP/0.9 doesn't support HTTP headers
}
