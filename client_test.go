package quic

import (
	"context"
	"crypto/tls"
	"net"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestDial(t *testing.T) {
	t.Run("Dial", func(t *testing.T) {
		testDial(t,
			func(ctx context.Context, addr net.Addr) error {
				conn := newUDPConnLocalhost(t)
				_, err := Dial(ctx, conn, addr, &tls.Config{}, nil)
				return err
			},
			false,
		)
	})

	t.Run("DialEarly", func(t *testing.T) {
		testDial(t,
			func(ctx context.Context, addr net.Addr) error {
				conn := newUDPConnLocalhost(t)
				_, err := DialEarly(ctx, conn, addr, &tls.Config{}, nil)
				return err
			},
			false,
		)
	})

	t.Run("DialAddr", func(t *testing.T) {
		testDial(t,
			func(ctx context.Context, addr net.Addr) error {
				_, err := DialAddr(ctx, addr.String(), &tls.Config{}, nil)
				return err
			},
			true,
		)
	})

	t.Run("DialAddrEarly", func(t *testing.T) {
		testDial(t,
			func(ctx context.Context, addr net.Addr) error {
				_, err := DialAddrEarly(ctx, addr.String(), &tls.Config{}, nil)
				return err
			},
			true,
		)
	})
}

func testDial(t *testing.T,
	dialFn func(context.Context, net.Addr) error,
	shouldCloseConn bool,
) {
	server := newUDPConnLocalhost(t)

	ctx, cancel := context.WithCancel(context.Background())
	errChan := make(chan error, 1)
	go func() { errChan <- dialFn(ctx, server.LocalAddr()) }()

	_, addr, err := server.ReadFrom(make([]byte, 1500))
	require.NoError(t, err)
	require.True(t, areTransportsRunning())
	cancel()
	select {
	case err := <-errChan:
		require.ErrorIs(t, err, context.Canceled)
	case <-time.After(time.Second):
		t.Fatal("timeout")
	}

	// The socket that the client used for dialing should be closed now.
	// Binding to the same address would error if the address was still in use.
	conn, err := net.ListenUDP("udp", addr.(*net.UDPAddr))
	if shouldCloseConn {
		require.NoError(t, err)
		defer conn.Close()
	} else {
		require.Error(t, err)
		if runtime.GOOS == "windows" {
			require.ErrorContains(t, err, "bind: Only one usage of each socket address")
		} else {
			require.ErrorContains(t, err, "address already in use")
		}
	}

	require.False(t, areTransportsRunning())
}
