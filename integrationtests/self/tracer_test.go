package self_test

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	mrand "math/rand/v2"
	"sync"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/utils"
	"github.com/quic-go/quic-go/logging"
	"github.com/quic-go/quic-go/metrics"
	"github.com/quic-go/quic-go/qlog"

	"github.com/stretchr/testify/require"
)

func TestTracerHandshake(t *testing.T) {
	addTracers := func(pers protocol.Perspective, conf *quic.Config) *quic.Config {
		enableQlog := mrand.Int()%2 != 0
		enableMetrics := mrand.Int()%2 != 0
		enableCustomTracer := mrand.Int()%2 != 0

		t.Logf("%s using qlog: %t, metrics: %t, custom: %t", pers, enableQlog, enableMetrics, enableCustomTracer)

		var tracerConstructors []func(context.Context, logging.Perspective, quic.ConnectionID) *logging.ConnectionTracer
		if enableQlog {
			tracerConstructors = append(tracerConstructors, func(_ context.Context, p logging.Perspective, connID quic.ConnectionID) *logging.ConnectionTracer {
				if mrand.Int()%2 == 0 { // simulate that a qlog collector might only want to log some connections
					t.Logf("%s qlog tracer deciding to not trace connection %s", p, connID)
					return nil
				}
				t.Logf("%s qlog tracing connection %s", p, connID)
				return qlog.NewConnectionTracer(utils.NewBufferedWriteCloser(bufio.NewWriter(&bytes.Buffer{}), io.NopCloser(nil)), p, connID)
			})
		}
		if enableMetrics {
			tracerConstructors = append(tracerConstructors, metrics.DefaultConnectionTracer)
		}
		if enableCustomTracer {
			tracerConstructors = append(tracerConstructors, func(context.Context, logging.Perspective, quic.ConnectionID) *logging.ConnectionTracer {
				return &logging.ConnectionTracer{}
			})
		}
		c := conf.Clone()
		c.Tracer = func(ctx context.Context, p logging.Perspective, connID quic.ConnectionID) *logging.ConnectionTracer {
			tracers := make([]*logging.ConnectionTracer, 0, len(tracerConstructors))
			for _, c := range tracerConstructors {
				if tr := c(ctx, p, connID); tr != nil {
					tracers = append(tracers, tr)
				}
			}
			return logging.NewMultiplexedConnectionTracer(tracers...)
		}
		return c
	}

	for i := 0; i < 3; i++ {
		t.Run(fmt.Sprintf("run %d", i+1), func(t *testing.T) {
			if enableQlog {
				t.Skip("This test sets tracers and won't produce any qlogs.")
			}

			quicClientConf := addTracers(protocol.PerspectiveClient, getQuicConfig(nil))
			quicServerConf := addTracers(protocol.PerspectiveServer, getQuicConfig(nil))

			ln, err := quic.Listen(newUDPConnLocalhost(t), getTLSConfig(), quicServerConf)
			require.NoError(t, err)
			t.Cleanup(func() { require.NoError(t, ln.Close()) })

			var wg sync.WaitGroup
			for j := 0; j < 3; j++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					ctx, cancel := context.WithTimeout(context.Background(), time.Second)
					defer cancel()
					conn, err := quic.Dial(ctx, newUDPConnLocalhost(t), ln.Addr(), getTLSClientConfig(), quicClientConf)
					require.NoError(t, err)
					defer conn.CloseWithError(0, "")

					sconn, err := ln.Accept(ctx)
					if err != nil {
						return
					}
					sstr, err := sconn.OpenUniStream()
					require.NoError(t, err)
					_, err = sstr.Write(PRData)
					require.NoError(t, err)
					require.NoError(t, sstr.Close())

					str, err := conn.AcceptUniStream(ctx)
					require.NoError(t, err)
					data, err := io.ReadAll(str)
					require.NoError(t, err)
					require.Equal(t, PRData, data)
				}()
			}
			wg.Wait()
		})
	}
}
