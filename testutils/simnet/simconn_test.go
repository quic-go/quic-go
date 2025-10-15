package simnet

import (
	"crypto/rand"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func randomPublicIPv4() net.IP {
start:
	ip := make([]byte, 4)
	rand.Read(ip[:])
	if net.IP(ip).IsPrivate() || net.IP(ip).IsLoopback() || net.IP(ip).IsLinkLocalUnicast() {
		goto start
	}
	return ip
}

func TestSimConnBasicConnectivity(t *testing.T) {
	router := &PerfectRouter{}

	// Create two endpoints
	addr1 := &net.UDPAddr{IP: randomPublicIPv4(), Port: 1234}
	addr2 := &net.UDPAddr{IP: randomPublicIPv4(), Port: 1234}

	conn1 := NewSimConn(addr1, router)
	conn2 := NewSimConn(addr2, router)

	// Test sending data from conn1 to conn2
	testData := []byte("hello world")
	n, err := conn1.WriteTo(testData, addr2)
	require.NoError(t, err)
	require.Equal(t, len(testData), n)

	// Read data from conn2
	buf := make([]byte, 1024)
	n, addr, err := conn2.ReadFrom(buf)
	require.NoError(t, err)
	require.Equal(t, testData, buf[:n])
	require.Equal(t, addr1, addr)

	// Check stats
	stats1 := conn1.Stats()
	require.Equal(t, len(testData), stats1.BytesSent)
	require.Equal(t, 1, stats1.PacketsSent)

	stats2 := conn2.Stats()
	require.Equal(t, len(testData), stats2.BytesRcvd)
	require.Equal(t, 1, stats2.PacketsRcvd)
}

func TestSimConnDeadlines(t *testing.T) {
	router := &PerfectRouter{}

	addr1 := &net.UDPAddr{IP: randomPublicIPv4(), Port: 1234}
	conn := NewSimConn(addr1, router)

	t.Run("read deadline", func(t *testing.T) {
		deadline := time.Now().Add(10 * time.Millisecond)
		err := conn.SetReadDeadline(deadline)
		require.NoError(t, err)

		buf := make([]byte, 1024)
		_, _, err = conn.ReadFrom(buf)
		require.ErrorIs(t, err, ErrDeadlineExceeded)
	})

	t.Run("write deadline", func(t *testing.T) {
		deadline := time.Now().Add(-time.Second) // Already expired
		err := conn.SetWriteDeadline(deadline)
		require.NoError(t, err)

		_, err = conn.WriteTo([]byte("test"), &net.UDPAddr{})
		require.ErrorIs(t, err, ErrDeadlineExceeded)
	})
}

func TestSimConnClose(t *testing.T) {
	router := &PerfectRouter{}

	addr1 := &net.UDPAddr{IP: randomPublicIPv4(), Port: 1234}
	conn := NewSimConn(addr1, router)

	err := conn.Close()
	require.NoError(t, err)

	// Verify operations fail after close
	_, err = conn.WriteTo([]byte("test"), addr1)
	require.ErrorIs(t, err, net.ErrClosed)

	buf := make([]byte, 1024)
	_, _, err = conn.ReadFrom(buf)
	require.ErrorIs(t, err, net.ErrClosed)

	// Second close should not error
	err = conn.Close()
	require.NoError(t, err)
}

func TestSimConnDeadlinesWithLatency(t *testing.T) {
	router := &FixedLatencyRouter{
		PerfectRouter: PerfectRouter{},
		latency:       100 * time.Millisecond,
	}

	addr1 := &net.UDPAddr{IP: randomPublicIPv4(), Port: 1234}
	addr2 := &net.UDPAddr{IP: randomPublicIPv4(), Port: 1234}

	conn1 := NewSimConn(addr1, router)
	conn2 := NewSimConn(addr2, router)

	reset := func() {
		router.RemoveNode(addr1)
		router.RemoveNode(addr2)

		conn1 = NewSimConn(addr1, router)
		conn2 = NewSimConn(addr2, router)
	}

	t.Run("write succeeds within deadline", func(t *testing.T) {
		deadline := time.Now().Add(200 * time.Millisecond)
		err := conn1.SetWriteDeadline(deadline)
		require.NoError(t, err)

		n, err := conn1.WriteTo([]byte("test"), addr2)
		require.NoError(t, err)
		require.Equal(t, 4, n)
		reset()
	})

	t.Run("write fails after past deadline", func(t *testing.T) {
		deadline := time.Now().Add(-time.Second) // Already expired
		err := conn1.SetWriteDeadline(deadline)
		require.NoError(t, err)

		_, err = conn1.WriteTo([]byte("test"), addr2)
		require.ErrorIs(t, err, ErrDeadlineExceeded)
		reset()
	})

	t.Run("read succeeds within deadline", func(t *testing.T) {
		// Reset deadline and send a message
		conn2.SetReadDeadline(time.Time{})
		testData := []byte("hello")
		deadline := time.Now().Add(200 * time.Millisecond)
		conn1.SetWriteDeadline(deadline)
		_, err := conn1.WriteTo(testData, addr2)
		require.NoError(t, err)

		// Set read deadline and try to read
		deadline = time.Now().Add(200 * time.Millisecond)
		err = conn2.SetReadDeadline(deadline)
		require.NoError(t, err)

		buf := make([]byte, 1024)
		n, addr, err := conn2.ReadFrom(buf)
		require.NoError(t, err)
		require.Equal(t, addr1, addr)
		require.Equal(t, testData, buf[:n])
		reset()
	})

	t.Run("read fails after deadline", func(t *testing.T) {
		defer reset()
		// Set a short deadline
		deadline := time.Now().Add(50 * time.Millisecond) // Less than router latency
		err := conn2.SetReadDeadline(deadline)
		require.NoError(t, err)

		var wg sync.WaitGroup
		defer wg.Wait()
		wg.Add(1)
		go func() {
			defer wg.Done()
			// Send data after setting deadline
			_, err := conn1.WriteTo([]byte("test"), addr2)
			require.NoError(t, err)
		}()

		// Read should fail due to deadline
		buf := make([]byte, 1024)
		_, _, err = conn2.ReadFrom(buf)
		require.ErrorIs(t, err, ErrDeadlineExceeded)
	})
}
