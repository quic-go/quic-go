package self_test

import (
	"fmt"
	"io"
	"net/http"
	"testing"
	"testing/synctest"

	"github.com/quic-go/quic-go/http3"

	"github.com/stretchr/testify/require"
)

func TestHTTP3StreamPriority(t *testing.T) {
	for _, test := range streamPriorityTests {
		t.Run(test.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				client, server := newStreamPriorityTestConnections(t)

				paths := [...]string{"/0", "/1", "/2", "/3"}
				started := make(chan struct{}, len(paths))
				startWrites := make(chan struct{}, len(paths))
				t.Cleanup(func() { close(startWrites) })
				serverWriteErrs := make(chan error, len(paths))
				mux := http.NewServeMux()
				for i, path := range paths {
					mux.HandleFunc("GET "+path, func(w http.ResponseWriter, _ *http.Request) {
						started <- struct{}{}
						<-startWrites
						_, err := w.Write(PRData[:test.sizes[i]])
						serverWriteErrs <- err
					})
				}
				h3Server := &http3.Server{Handler: mux}
				go h3Server.ServeQUICConn(server)

				cc := (&http3.Transport{}).NewClientConn(client)
				t.Cleanup(func() { cc.CloseWithError(0, "") })
				var streams [4]*http3.RequestStream
				for i := range streams {
					str, err := cc.OpenRequestStream(t.Context())
					require.NoError(t, err)
					req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "https://example.com"+paths[i], nil)
					require.NoError(t, err)
					priority := fmt.Sprintf("u=%d", test.urgencies[i])
					if test.incremental {
						priority += ", i"
					}
					req.Header.Set("Priority", priority)
					require.NoError(t, str.SendRequestHeader(req))
					require.NoError(t, str.Close())
					streams[i] = str
				}
				for range streams {
					<-started
				}

				type readResult struct {
					i   int
					n   int64
					err error
				}
				completed := make(chan readResult, len(streams))
				for i, str := range streams {
					go func() {
						resp, err := str.ReadResponse()
						var n int64
						if err == nil {
							n, err = io.Copy(io.Discard, resp.Body)
							resp.Body.Close()
						}
						completed <- readResult{i: i, n: n, err: err}
					}()
				}
				for range streams {
					startWrites <- struct{}{}
				}

				for _, i := range test.order {
					result := <-completed
					require.NoError(t, result.err)
					require.Equal(t, i, result.i)
					require.EqualValues(t, test.sizes[i], result.n)
				}
				for range streams {
					require.NoError(t, <-serverWriteErrs)
				}
			})
		})
	}
}
