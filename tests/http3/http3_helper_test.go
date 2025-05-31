package http3

import (
	"net"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func newUDPConnLocalhost(t testing.TB) *net.UDPConn {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })
	return conn
}

func scaleDuration(t time.Duration) time.Duration {
	scaleFactor := 1
	if f, err := strconv.Atoi(os.Getenv("TIMESCALE_FACTOR")); err == nil { // parsing "" errors, so this works fine if the env is not set
		scaleFactor = f
	}
	if scaleFactor == 0 {
		panic("TIMESCALE_FACTOR is 0")
	}
	return time.Duration(scaleFactor) * t
}
