package self_test

import (
	"context"
	"io"
	"net"
	"net/http"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/stretchr/testify/require"
)

type listenerWrapper struct {
	http3.QUICEarlyListener
	listenerClosed bool
	count          atomic.Int32
}

func (ln *listenerWrapper) Close() error {
	ln.listenerClosed = true
	return ln.QUICEarlyListener.Close()
}

func (ln *listenerWrapper) Faker() *fakeClosingListener {
	ln.count.Add(1)
	ctx, cancel := context.WithCancel(context.Background())
	return &fakeClosingListener{
		listenerWrapper: ln,
		ctx:             ctx,
		cancel:          cancel,
	}
}

type fakeClosingListener struct {
	*listenerWrapper
	closed atomic.Bool
	ctx    context.Context
	cancel context.CancelFunc
}

func (ln *fakeClosingListener) Accept(ctx context.Context) (quic.EarlyConnection, error) {
	return ln.listenerWrapper.Accept(ln.ctx)
}

func (ln *fakeClosingListener) Close() error {
	if ln.closed.CompareAndSwap(false, true) {
		ln.cancel()
		if ln.listenerWrapper.count.Add(-1) == 0 {
			ln.listenerWrapper.Close()
		}
	}
	return nil
}

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
	quicLn, err := quic.ListenEarly(newUDPConnLocalhost(t), tlsConf, getQuicConfig(nil))
	require.NoError(t, err)
	ln := &listenerWrapper{QUICEarlyListener: quicLn}
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
	fake1 := ln.Faker()
	stoppedServing1 := make(chan struct{})
	go func() {
		server1.ServeListener(fake1)
		close(stoppedServing1)
	}()

	resp, err := client.Get("https://localhost:" + port + "/hello1")
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.Equal(t, "Hello, World 1!\n", string(body))

	// open second server with same underlying listener
	fake2 := ln.Faker()
	stoppedServing2 := make(chan struct{})
	go func() {
		server2.ServeListener(fake2)
		close(stoppedServing2)
	}()

	// Verify both servers are running by waiting a bit and checking channels aren't closed
	time.Sleep(50 * time.Millisecond)
	select {
	case <-stoppedServing1:
		t.Fatal("server1 stopped unexpectedly")
	case <-stoppedServing2:
		t.Fatal("server2 stopped unexpectedly")
	default:
	}

	// now close first server
	require.NoError(t, server1.Close())
	select {
	case <-stoppedServing1:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for server1 to stop")
	}
	require.True(t, fake1.closed.Load())
	require.False(t, fake2.closed.Load())
	require.False(t, ln.listenerClosed)
	require.NoError(t, client.Transport.(*http3.Transport).Close())

	// verify that new connections are being initiated from the second server now
	resp, err = client.Get("https://localhost:" + port + "/hello2")
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	body, err = io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.Equal(t, "Hello, World 2!\n", string(body))

	// close the other server - both the fake and the actual listeners must close now
	require.NoError(t, server2.Close())
	select {
	case <-stoppedServing2:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for server2 to stop")
	}
	require.True(t, fake2.closed.Load())
	require.True(t, ln.listenerClosed)
}
