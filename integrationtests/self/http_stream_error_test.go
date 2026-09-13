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

			switch errorType {
			case "stream cancellation":
				clientStr.CancelWrite(quic.StreamErrorCode(http3.ErrCodeExcessiveLoad))

				_, err = clientStr.Write([]byte{0})
				require.ErrorIs(t, err, &http3.Error{ErrorCode: http3.ErrCodeExcessiveLoad, Remote: false}, "RequestStream.Write")
				_, err = serverStr.Read([]byte{0})
				require.ErrorIs(t, err, &http3.Error{ErrorCode: http3.ErrCodeExcessiveLoad, Remote: true}, "Stream.Read")

				serverStr.CancelWrite(quic.StreamErrorCode(http3.ErrCodeExcessiveLoad))
				_, err = serverStr.Write([]byte{0})
				require.ErrorIs(t, err, &http3.Error{ErrorCode: http3.ErrCodeExcessiveLoad, Remote: false}, "Stream.Write")
				_, err = clientStr.Read([]byte{0})
				require.ErrorIs(t, err, &http3.Error{ErrorCode: http3.ErrCodeExcessiveLoad, Remote: true}, "RequestStream.Read")
			case "application close":
				require.NoError(t, conn.CloseWithError(quic.ApplicationErrorCode(http3.ErrCodeExcessiveLoad), ""))

				_, err = clientStr.Write([]byte{0})
				require.ErrorIs(t, err, &http3.Error{ErrorCode: http3.ErrCodeExcessiveLoad, Remote: false}, "RequestStream.Write")
				_, err = serverStr.Read([]byte{0})
				require.ErrorIs(t, err, &http3.Error{ErrorCode: http3.ErrCodeExcessiveLoad, Remote: true}, "Stream.Read")
				_, err = serverStr.Write([]byte{0})
				require.ErrorIs(t, err, &http3.Error{ErrorCode: http3.ErrCodeExcessiveLoad, Remote: true}, "Stream.Write")
				_, err = clientStr.Read([]byte{0})
				require.ErrorIs(t, err, &http3.Error{ErrorCode: http3.ErrCodeExcessiveLoad, Remote: false}, "RequestStream.Read")
			}
		})
	}
}
