package http3

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/stretchr/testify/require"
)

func TestServerReadHeaderTimeout(t *testing.T) {
	for _, timeout := range []time.Duration{100 * time.Millisecond, 0, -time.Second} {
		t.Run(timeout.String(), func(t *testing.T) {
			client, conn := newConnPair(t)
			called := make(chan struct{}, 1)
			server := &Server{
				ReadHeaderTimeout: timeout,
				Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					called <- struct{}{}
					w.WriteHeader(http.StatusNoContent)
				}),
			}
			go server.ServeQUICConn(conn)
			defer server.Close()
			stream, err := client.OpenStream()
			require.NoError(t, err)
			request := encodeRequest(t, httptest.NewRequest(http.MethodGet, "https://example.com/", nil))
			_, err = stream.Write(request[:1])
			require.NoError(t, err)
			if timeout > 0 {
				expectStreamReadReset(t, stream, quic.StreamErrorCode(ErrCodeRequestIncomplete))
				select {
				case <-called:
					t.Fatal("handler received an incomplete header")
				default:
				}
				return
			}
			time.Sleep(200 * time.Millisecond)
			_, err = stream.Write(request[1:])
			require.NoError(t, err)
			require.NoError(t, stream.Close())
			require.NoError(t, stream.SetReadDeadline(time.Now().Add(time.Second)))
			require.Equal(t, []string{"204"}, decodeHeader(t, stream)[":status"])
		})
	}
}

func TestServerHeaderTimeoutDoesNotLimitBody(t *testing.T) {
	client, conn := newConnPair(t)
	reading := make(chan struct{})
	bodyResult := make(chan error, 1)
	server := &Server{
		ReadHeaderTimeout: 100 * time.Millisecond,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			close(reading)
			_, err := io.ReadAll(req.Body)
			bodyResult <- err
			w.WriteHeader(http.StatusNoContent)
		}),
	}
	go server.ServeQUICConn(conn)
	defer server.Close()
	stream, err := client.OpenStream()
	require.NoError(t, err)
	request := encodeRequest(t, httptest.NewRequest(http.MethodPost, "https://example.com/", strings.NewReader("body")))
	_, err = stream.Write(request[:len(request)-4])
	require.NoError(t, err)
	select {
	case <-reading:
	case <-time.After(time.Second):
		t.Fatal("handler did not start")
	}
	time.Sleep(2 * server.ReadHeaderTimeout)
	_, err = stream.Write(request[len(request)-4:])
	require.NoError(t, err)
	require.NoError(t, stream.Close())
	select {
	case err := <-bodyResult:
		require.NoError(t, err)
	case <-time.After(time.Second):
		t.Fatal("body read did not finish")
	}
	require.NoError(t, stream.SetReadDeadline(time.Now().Add(time.Second)))
	require.Equal(t, []string{"204"}, decodeHeader(t, stream)[":status"])
}
