package quic

import (
	"bytes"
	"fmt"
	"net"
	"os"
	"runtime/pprof"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// in the tests for the stream deadlines we set a deadline
// and wait to make an assertion when Read / Write was unblocked
// on the CIs, the timing is a lot less precise, so scale every duration by this factor
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

func newUDPConnLocalhost(t testing.TB) *net.UDPConn {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })
	return conn
}

func areConnsRunning() bool {
	var b bytes.Buffer
	pprof.Lookup("goroutine").WriteTo(&b, 1)
	return strings.Contains(b.String(), "quic-go.(*connection).run")
}

func areTransportsRunning() bool {
	var b bytes.Buffer
	pprof.Lookup("goroutine").WriteTo(&b, 1)
	return strings.Contains(b.String(), "quic-go.(*Transport).listen")
}

func TestMain(m *testing.M) {
	status := m.Run()
	if status != 0 {
		os.Exit(status)
	}
	if areConnsRunning() {
		fmt.Println("stray connection goroutines found")
		os.Exit(1)
	}
	if areTransportsRunning() {
		fmt.Println("stray transport goroutines found")
		os.Exit(1)
	}
	os.Exit(status)
}
