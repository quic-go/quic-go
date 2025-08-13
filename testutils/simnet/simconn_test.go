package simnet

import (
	"bytes"
	"net"
	"sync"
	"testing"
	"testing/quick"
	"time"

	"github.com/marcopolo/simnet/internal/require"
)

func TestSimConnBasicConnectivity(t *testing.T) {
	router := &PerfectRouter{}

	// Create two endpoints
	addr1 := &net.UDPAddr{IP: IntToPublicIPv4(1), Port: 1234}
	addr2 := &net.UDPAddr{IP: IntToPublicIPv4(2), Port: 1234}

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

	addr1 := &net.UDPAddr{IP: IntToPublicIPv4(1), Port: 1234}
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

	addr1 := &net.UDPAddr{IP: IntToPublicIPv4(1), Port: 1234}
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

func TestSimConnLocalAddr(t *testing.T) {
	router := &PerfectRouter{}

	addr1 := &net.UDPAddr{IP: IntToPublicIPv4(1), Port: 1234}
	conn := NewSimConn(addr1, router)

	// Test default local address
	require.Equal(t, addr1, conn.LocalAddr())

	// Test setting custom local address
	customAddr := &net.UDPAddr{IP: IntToPublicIPv4(3), Port: 5678}
	conn.SetLocalAddr(customAddr)
	require.Equal(t, customAddr, conn.LocalAddr())
}

func TestSimConnDeadlinesWithLatency(t *testing.T) {
	router := &FixedLatencyRouter{
		PerfectRouter: PerfectRouter{},
		latency:       100 * time.Millisecond,
	}

	addr1 := &net.UDPAddr{IP: IntToPublicIPv4(1), Port: 1234}
	addr2 := &net.UDPAddr{IP: IntToPublicIPv4(2), Port: 1234}

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

func TestSimpleHolePunch(t *testing.T) {
	router := &SimpleFirewallRouter{
		nodes: make(map[string]*simpleNodeFirewall),
	}

	// Create two peers
	addr1 := &net.UDPAddr{IP: IntToPublicIPv4(1), Port: 1234}
	addr2 := &net.UDPAddr{IP: IntToPublicIPv4(2), Port: 1234}

	peer1 := NewSimConn(addr1, router)
	peer2 := NewSimConn(addr2, router)

	reset := func() {
		router.RemoveNode(addr1)
		router.RemoveNode(addr2)

		peer1 = NewSimConn(addr1, router)
		peer2 = NewSimConn(addr2, router)
	}

	// Initially, direct communication between peer1 and peer2 should fail
	t.Run("direct communication blocked initially", func(t *testing.T) {
		_, err := peer1.WriteTo([]byte("direct message"), addr2)
		require.NoError(t, err) // Write succeeds but packet is dropped

		// Try to read from peer2
		peer2.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
		buf := make([]byte, 1024)
		_, _, err = peer2.ReadFrom(buf)
		require.ErrorIs(t, err, ErrDeadlineExceeded)
		reset()
	})

	holePunchMsg := []byte("hole punch")
	// Simulate hole punching
	t.Run("hole punch and direct communication", func(t *testing.T) {
		// Both peers send packets to each other simultaneously
		var wg sync.WaitGroup
		wg.Add(2)

		go func() {
			defer wg.Done()
			_, err := peer1.WriteTo(holePunchMsg, addr2)
			require.NoError(t, err)
		}()

		go func() {
			defer wg.Done()
			_, err := peer2.WriteTo(holePunchMsg, addr1)
			require.NoError(t, err)
		}()

		wg.Wait()

		// Now direct communication should work both ways
		t.Run("peer1 to peer2", func(t *testing.T) {
			testMsg := []byte("direct message after hole punch")
			_, err := peer1.WriteTo(testMsg, addr2)
			require.NoError(t, err)

			buf := make([]byte, 1024)
			peer2.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
			n, addr, err := peer2.ReadFrom(buf)
			require.NoError(t, err)
			require.Equal(t, addr1, addr)
			if bytes.Equal(buf[:n], holePunchMsg) {
				// Read again to get the actual message
				n, addr, err = peer2.ReadFrom(buf)
				require.NoError(t, err)
				require.Equal(t, addr1, addr)
			}
			require.Equal(t, string(testMsg), string(buf[:n]))
		})

		t.Run("peer2 to peer1", func(t *testing.T) {
			testMsg := []byte("response from peer2")
			_, err := peer2.WriteTo(testMsg, addr1)
			require.NoError(t, err)

			buf := make([]byte, 1024)
			peer1.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
			n, addr, err := peer1.ReadFrom(buf)
			require.NoError(t, err)
			require.Equal(t, addr2, addr)
			if bytes.Equal(buf[:n], holePunchMsg) {
				// Read again to get the actual message
				n, addr, err = peer1.ReadFrom(buf)
				require.NoError(t, err)
				require.Equal(t, addr2, addr)
			}
			require.Equal(t, string(testMsg), string(buf[:n]))
		})
	})
}

func TestPublicIP(t *testing.T) {
	err := quick.Check(func(n int) bool {
		ip := IntToPublicIPv4(n)
		return !ip.IsPrivate()
	}, nil)
	require.NoError(t, err)
}
