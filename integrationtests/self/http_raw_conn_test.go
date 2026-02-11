package self_test

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/quic-go/quicvarint"

	"github.com/stretchr/testify/require"
)

// This test tests the HTTP/3 raw connection functionality,
// which is primarily used by WebTransport.
func TestHTTPRawConn(t *testing.T) {
	const magicValue = 0x123456

	synctest.Test(t, func(t *testing.T) {
		const rtt = 10 * time.Millisecond

		clientPacketConn, serverPacketConn, closeFn := newSimnetLink(t, rtt)
		defer closeFn(t)

		ln, err := quic.ListenEarly(
			serverPacketConn,
			http3.ConfigureTLSConfig(getTLSConfig()),
			getQuicConfig(&quic.Config{EnableDatagrams: true}),
		)
		require.NoError(t, err)
		defer ln.Close()

		start := time.Now()

		mux := http.NewServeMux()
		mux.HandleFunc("/data", func(w http.ResponseWriter, r *http.Request) { w.Write(PRData) })
		server := &http3.Server{
			Handler:         mux,
			EnableDatagrams: true,
		}
		defer server.Close()

		// run the server in a separate Goroutine, so we can make sure that SETTINGS are sent in 0.5-RTT data
		errChan := make(chan error, 1)
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			serverConn, err := ln.Accept(ctx)
			if err != nil {
				errChan <- err
				return
			}

			rawServerConn, err := server.NewRawServerConn(serverConn)
			if err != nil {
				errChan <- err
				return
			}
			var wg sync.WaitGroup
			wg.Add(2)
			// accept and handle unidirectional streams opened by the client
			go func() {
				defer wg.Done()
				for {
					str, err := serverConn.AcceptUniStream(context.Background())
					if err != nil {
						return
					}
					go rawServerConn.HandleUnidirectionalStream(str)
				}
			}()
			// accept and handle bidirectional streams opened by the client
			go func() {
				defer wg.Done()
				for {
					str, err := serverConn.AcceptStream(context.Background())
					if err != nil {
						return
					}
					v, _ := quicvarint.Peek(str)
					if v == magicValue {
						go func() {
							// read the previously peeked value
							quicvarint.Read(quicvarint.NewReader(str))
							defer str.Close()
							io.Copy(str, str)
						}()
					} else {
						go rawServerConn.HandleRequestStream(str)
					}
				}
			}()
			wg.Wait()
			<-serverConn.Context().Done()
			errChan <- nil
		}()

		ctx, cancel := context.WithTimeout(context.Background(), time.Hour)
		defer cancel()
		clientConn, err := quic.Dial(
			ctx,
			clientPacketConn,
			serverPacketConn.LocalAddr(),
			http3.ConfigureTLSConfig(getTLSClientConfig()),
			getQuicConfig(&quic.Config{EnableDatagrams: true}),
		)
		require.NoError(t, err)
		defer clientConn.CloseWithError(0, "")

		tr := &http3.Transport{
			EnableDatagrams: true,
		}
		rawClientConn := tr.NewRawClientConn(clientConn)
		// accept and handle unidirectional streams opened by the server
		go func() {
			for {
				str, err := clientConn.AcceptUniStream(ctx)
				if err != nil {
					return
				}
				go rawClientConn.HandleUnidirectionalStream(str)
			}
		}()

		select {
		case <-rawClientConn.ReceivedSettings():
			settings := rawClientConn.Settings()
			require.True(t, settings.EnableDatagrams)
			// the server sends SETTINGS in 0.5-RTT data, so they should be received after 1 RTT
			require.Equal(t, rtt, time.Since(start))
		case <-time.After(time.Second):
			t.Fatal("timeout waiting for HTTP/3 settings")
		}

		req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("https://%s/data", serverPacketConn.LocalAddr().(*net.UDPAddr)), nil)
		require.NoError(t, err)
		reqStr, err := rawClientConn.OpenRequestStream(ctx)
		require.NoError(t, err)
		require.NoError(t, reqStr.SendRequestHeader(req))
		resp, err := reqStr.ReadResponse()
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, resp.StatusCode)
		data, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		require.Equal(t, PRData, data)
		require.NoError(t, resp.Body.Close())

		str, err := clientConn.OpenStream()
		require.NoError(t, err)
		b := quicvarint.Append(nil, magicValue)
		b = append(b, []byte("lorem ipsum dolor sit amet")...)
		_, err = str.Write(b)
		require.NoError(t, err)
		require.NoError(t, str.Close())
		data, err = io.ReadAll(str)
		require.NoError(t, err)
		require.Equal(t, []byte("lorem ipsum dolor sit amet"), data)

		clientConn.CloseWithError(0, "")
		select {
		case err := <-errChan:
			require.NoError(t, err)
		case <-time.After(time.Second):
			t.Fatal("timeout waiting for server to close")
		}
	})
}
