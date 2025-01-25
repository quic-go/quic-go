package self_test

import (
	"context"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	quicproxy "github.com/quic-go/quic-go/integrationtests/tools/proxy"
	"github.com/stretchr/testify/require"
)

func runServerForRTTTest(t *testing.T) (net.Addr, <-chan error) {
	ln, err := quic.Listen(
		newUPDConnLocalhost(t),
		getTLSConfig(),
		getQuicConfig(nil),
	)
	require.NoError(t, err)
	t.Cleanup(func() { ln.Close() })

	errChan := make(chan error, 1)
	go func() {
		defer close(errChan)
		for {
			conn, err := ln.Accept(context.Background())
			if err != nil {
				errChan <- fmt.Errorf("accept error: %w", err)
				return
			}
			str, err := conn.OpenStream()
			if err != nil {
				errChan <- fmt.Errorf("open stream error: %w", err)
				return
			}
			_, err = str.Write(PRData)
			if err != nil {
				errChan <- fmt.Errorf("write error: %w", err)
				return
			}
			str.Close()
		}
	}()

	return ln.Addr(), errChan
}

func TestDownloadWithFixedRTT(t *testing.T) {
	addr, errChan := runServerForRTTTest(t)

	for _, rtt := range []time.Duration{
		10 * time.Millisecond,
		100 * time.Millisecond,
		250 * time.Millisecond,
	} {
		t.Run(fmt.Sprintf("RTT %s", rtt), func(t *testing.T) {
			t.Cleanup(func() {
				select {
				case err := <-errChan:
					t.Errorf("server error: %v", err)
				default:
				}
			})

			proxy := quicproxy.Proxy{
				Conn:        newUPDConnLocalhost(t),
				ServerAddr:  &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: addr.(*net.UDPAddr).Port},
				DelayPacket: func(_ quicproxy.Direction, _ []byte) time.Duration { return rtt / 2 },
			}
			require.NoError(t, proxy.Start())
			t.Cleanup(func() { proxy.Close() })

			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			conn, err := quic.Dial(
				ctx,
				newUPDConnLocalhost(t),
				proxy.LocalAddr(),
				getTLSClientConfig(),
				getQuicConfig(nil),
			)
			require.NoError(t, err)
			defer conn.CloseWithError(0, "")

			str, err := conn.AcceptStream(ctx)
			require.NoError(t, err)
			data, err := io.ReadAll(str)
			require.NoError(t, err)
			require.Equal(t, PRData, data)
		})
	}
}

func TestDownloadWithReordering(t *testing.T) {
	addr, errChan := runServerForRTTTest(t)

	for _, rtt := range []time.Duration{
		5 * time.Millisecond,
		30 * time.Millisecond,
	} {
		t.Run(fmt.Sprintf("RTT %s", rtt), func(t *testing.T) {
			t.Cleanup(func() {
				select {
				case err := <-errChan:
					t.Errorf("server error: %v", err)
				default:
				}
			})

			proxy := quicproxy.Proxy{
				Conn:       newUPDConnLocalhost(t),
				ServerAddr: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: addr.(*net.UDPAddr).Port},
				DelayPacket: func(_ quicproxy.Direction, _ []byte) time.Duration {
					return randomDuration(rtt/2, rtt*3/2) / 2
				},
			}
			require.NoError(t, proxy.Start())
			t.Cleanup(func() { proxy.Close() })

			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			conn, err := quic.Dial(
				ctx,
				newUPDConnLocalhost(t),
				proxy.LocalAddr(),
				getTLSClientConfig(),
				getQuicConfig(nil),
			)
			require.NoError(t, err)
			defer conn.CloseWithError(0, "")

			str, err := conn.AcceptStream(ctx)
			require.NoError(t, err)
			data, err := io.ReadAll(str)
			require.NoError(t, err)
			require.Equal(t, PRData, data)
		})
	}
}
