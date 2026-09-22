package self_test

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"

	"github.com/stretchr/testify/require"
)

// Each case uses a fresh connection: either both peers cancel their write side or the client closes the connection.
// Reads and writes must return *http3.Error with H3_EXCESSIVE_LOAD and Remote indicating whether the peer caused the error.
func TestHTTPStreamErrors(t *testing.T) {
	for _, errorType := range []string{"stream cancellation", "application close"} {
		t.Run(errorType, func(t *testing.T) {
			serverStreams := make(chan *http3.Stream, 1)
			mux := http.NewServeMux()
			mux.HandleFunc("/cancel", func(w http.ResponseWriter, _ *http.Request) {
				serverStreams <- w.(http3.HTTPStreamer).HTTPStream()
			})
			port := startHTTPServer(t, mux)

			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			conn, err := quic.Dial(
				ctx,
				newUDPConnLocalhost(t),
				&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port},
				http3.ConfigureTLSConfig(getTLSClientConfigWithoutServerName()),
				getQuicConfig(nil),
			)
			require.NoError(t, err)
			defer conn.CloseWithError(0, "")
			cc := (&http3.Transport{}).NewClientConn(conn)
			clientStr, err := cc.OpenRequestStream(ctx)
			require.NoError(t, err)
			require.NoError(t, clientStr.SetDeadline(time.Now().Add(time.Second)))
			req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("https://localhost:%d/cancel", port), nil)
			require.NoError(t, err)
			require.NoError(t, clientStr.SendRequestHeader(req))
			_, err = clientStr.ReadResponse()
			require.NoError(t, err)
			serverStr := <-serverStreams
			require.NoError(t, serverStr.SetDeadline(time.Now().Add(time.Second)))

			local := &http3.Error{ErrorCode: http3.ErrCodeExcessiveLoad, Remote: false}
			remote := &http3.Error{ErrorCode: http3.ErrCodeExcessiveLoad, Remote: true}
			var expectedQUICErr error
			var expectedServerWriteErr, expectedClientReadErr *http3.Error
			switch errorType {
			case "stream cancellation":
				clientStr.CancelWrite(quic.StreamErrorCode(http3.ErrCodeExcessiveLoad))
				serverStr.CancelWrite(quic.StreamErrorCode(http3.ErrCodeExcessiveLoad))
				expectedQUICErr = &quic.StreamError{
					StreamID:  serverStr.StreamID(),
					ErrorCode: quic.StreamErrorCode(http3.ErrCodeExcessiveLoad),
					Remote:    true,
				}
				expectedServerWriteErr, expectedClientReadErr = local, remote
			case "application close":
				require.NoError(t, conn.CloseWithError(
					quic.ApplicationErrorCode(http3.ErrCodeExcessiveLoad),
					"",
				))
				expectedQUICErr = &quic.ApplicationError{
					ErrorCode: quic.ApplicationErrorCode(http3.ErrCodeExcessiveLoad),
					Remote:    true,
				}
				expectedServerWriteErr, expectedClientReadErr = remote, local
			}

			_, err = clientStr.Write([]byte{0})
			require.ErrorIs(t, err, local, "RequestStream.Write")
			_, err = serverStr.Read([]byte{0})
			require.ErrorIs(t, err, remote, "Stream.Read")
			require.ErrorIs(t, err, expectedQUICErr)
			if errorType == "application close" {
				require.ErrorIs(t, err, net.ErrClosed)
			} else {
				require.NotErrorIs(t, err, net.ErrClosed)
			}
			_, err = serverStr.Write([]byte{0})
			require.ErrorIs(t, err, expectedServerWriteErr, "Stream.Write")
			_, err = clientStr.Read([]byte{0})
			require.ErrorIs(t, err, expectedClientReadErr, "RequestStream.Read")
		})
	}
}
