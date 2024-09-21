package quicproxy

import (
	"bytes"
	"fmt"
	"net"
	"runtime"
	"runtime/pprof"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/wire"

	"github.com/stretchr/testify/require"
)

type packetData []byte

func makePacket(t *testing.T, p protocol.PacketNumber, payload []byte) []byte {
	t.Helper()
	hdr := wire.ExtendedHeader{
		Header: wire.Header{
			Type:             protocol.PacketTypeInitial,
			Version:          protocol.Version1,
			Length:           4 + protocol.ByteCount(len(payload)),
			DestConnectionID: protocol.ParseConnectionID([]byte{0xde, 0xad, 0xbe, 0xef, 0, 0, 0x13, 0x37}),
			SrcConnectionID:  protocol.ParseConnectionID([]byte{0xde, 0xad, 0xbe, 0xef, 0, 0, 0x13, 0x37}),
		},
		PacketNumber:    p,
		PacketNumberLen: protocol.PacketNumberLen4,
	}
	b, err := hdr.Append(nil, protocol.Version1)
	require.NoError(t, err)
	b = append(b, payload...)
	return b
}

func readPacketNumber(t *testing.T, b []byte) protocol.PacketNumber {
	t.Helper()
	hdr, data, _, err := wire.ParsePacket(b)
	require.NoError(t, err)
	require.Equal(t, protocol.PacketTypeInitial, hdr.Type)
	extHdr, err := hdr.ParseExtended(data)
	require.NoError(t, err)
	return extHdr.PacketNumber
}

func TestProxySetupt(t *testing.T) {
	proxy, err := NewQuicProxy("localhost:0", nil)
	require.NoError(t, err)
	require.Len(t, proxy.clientDict, 0)

	// Check that the proxy port is in use
	addr, err := net.ResolveUDPAddr("udp", "localhost:"+strconv.Itoa(proxy.LocalPort()))
	require.NoError(t, err)
	_, err = net.ListenUDP("udp", addr)
	if runtime.GOOS == "windows" {
		require.EqualError(t, err, fmt.Sprintf("listen udp 127.0.0.1:%d: bind: Only one usage of each socket address (protocol/network address/port) is normally permitted.", proxy.LocalPort()))
	} else {
		require.EqualError(t, err, fmt.Sprintf("listen udp 127.0.0.1:%d: bind: address already in use", proxy.LocalPort()))
	}

	require.Equal(t, "127.0.0.1:"+strconv.Itoa(proxy.LocalPort()), proxy.LocalAddr().String())
	require.NotZero(t, proxy.LocalPort())

	require.NoError(t, proxy.Close())
}

func TestProxyShutdown(t *testing.T) {
	isProxyRunning := func() bool {
		var b bytes.Buffer
		pprof.Lookup("goroutine").WriteTo(&b, 1)
		return strings.Contains(b.String(), "proxy.(*QuicProxy).runProxy")
	}

	proxy, err := NewQuicProxy("localhost:0", nil)
	require.NoError(t, err)
	port := proxy.LocalPort()
	require.Eventually(t, func() bool { return isProxyRunning() }, time.Second, 10*time.Millisecond)

	conn, err := net.DialUDP("udp", nil, proxy.LocalAddr().(*net.UDPAddr))
	require.NoError(t, err)
	_, err = conn.Write(makePacket(t, 1, []byte("foobar")))
	require.NoError(t, err)

	require.NoError(t, proxy.Close())

	// check that the proxy port is not in use anymore
	addr, err := net.ResolveUDPAddr("udp", "localhost:"+strconv.Itoa(port))
	require.NoError(t, err)
	// sometimes it takes a while for the OS to free the port
	require.Eventually(t, func() bool {
		ln, err := net.ListenUDP("udp", addr)
		if err != nil {
			return false
		}
		ln.Close()
		return true
	}, time.Second, 10*time.Millisecond)
	require.Eventually(t, func() bool { return !isProxyRunning() }, time.Second, 10*time.Millisecond)
}

// Set up a dumb UDP server.
// In production this would be a QUIC server.
func runServer(t *testing.T) (*net.UDPAddr, chan packetData) {
	serverConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	require.NoError(t, err)

	serverReceivedPackets := make(chan packetData, 100)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			buf := make([]byte, protocol.MaxPacketBufferSize)
			// the ReadFromUDP will error as soon as the UDP conn is closed
			n, addr, err := serverConn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			data := buf[:n]
			serverReceivedPackets <- packetData(data)
			if _, err := serverConn.WriteToUDP(data, addr); err != nil { // echo the packet

				return
			}
		}
	}()

	t.Cleanup(func() {
		require.NoError(t, serverConn.Close())
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatalf("timeout")
		}
	})

	return serverConn.LocalAddr().(*net.UDPAddr), serverReceivedPackets
}

func startProxy(t *testing.T, opts *Opts) (clientConn *net.UDPConn) {
	proxy, err := NewQuicProxy("localhost:0", opts)
	require.NoError(t, err)
	clientConn, err = net.DialUDP("udp", nil, proxy.LocalAddr().(*net.UDPAddr))
	require.NoError(t, err)

	t.Cleanup(func() {
		require.NoError(t, proxy.Close())
		require.NoError(t, clientConn.Close())
	})
	return clientConn
}

func TestProxyyingBackAndForth(t *testing.T) {
	serverAddr, _ := runServer(t)
	clientConn := startProxy(t, &Opts{RemoteAddr: serverAddr.String()})

	// send the first packet
	_, err := clientConn.Write(makePacket(t, 1, []byte("foobar")))
	require.NoError(t, err)
	// send the second packet
	_, err = clientConn.Write(makePacket(t, 2, []byte("decafbad")))
	require.NoError(t, err)

	buf := make([]byte, 1024)
	n, err := clientConn.Read(buf)
	require.NoError(t, err)
	require.Contains(t, string(buf[:n]), "foobar")
	n, err = clientConn.Read(buf)
	require.NoError(t, err)
	require.Contains(t, string(buf[:n]), "decafbad")
}

func TestDropIncomingPackets(t *testing.T) {
	const numPackets = 6
	serverAddr, serverReceivedPackets := runServer(t)
	var counter atomic.Int32
	clientConn := startProxy(t, &Opts{
		RemoteAddr: serverAddr.String(),
		DropPacket: func(d Direction, _ []byte) bool {
			if d != DirectionIncoming {
				return false
			}
			return counter.Add(1)%2 == 1
		},
	})

	for i := 1; i <= numPackets; i++ {
		_, err := clientConn.Write(makePacket(t, protocol.PacketNumber(i), []byte("foobar"+strconv.Itoa(i))))
		require.NoError(t, err)
	}

	for i := 0; i < numPackets/2; i++ {
		select {
		case <-serverReceivedPackets:
		case <-time.After(time.Second):
			t.Fatalf("timeout")
		}
	}
	select {
	case <-serverReceivedPackets:
		t.Fatalf("received unexpected packet")
	case <-time.After(100 * time.Millisecond):
	}
}

func TestDropOutgoingPackets(t *testing.T) {
	const numPackets = 6
	serverAddr, serverReceivedPackets := runServer(t)
	var counter atomic.Int32
	clientConn := startProxy(t, &Opts{
		RemoteAddr: serverAddr.String(),
		DropPacket: func(d Direction, _ []byte) bool {
			if d != DirectionOutgoing {
				return false
			}
			return counter.Add(1)%2 == 1
		},
	})

	clientReceivedPackets := make(chan struct{}, numPackets)
	// receive the packets echoed by the server on client side
	go func() {
		for {
			buf := make([]byte, protocol.MaxPacketBufferSize)
			// the ReadFromUDP will error as soon as the UDP conn is closed
			if _, _, err := clientConn.ReadFromUDP(buf); err != nil {
				return
			}
			clientReceivedPackets <- struct{}{}
		}
	}()

	for i := 1; i <= numPackets; i++ {
		_, err := clientConn.Write(makePacket(t, protocol.PacketNumber(i), []byte("foobar"+strconv.Itoa(i))))
		require.NoError(t, err)
	}

	for i := 0; i < numPackets/2; i++ {
		select {
		case <-clientReceivedPackets:
		case <-time.After(time.Second):
			t.Fatalf("timeout")
		}
	}
	select {
	case <-clientReceivedPackets:
		t.Fatalf("received unexpected packet")
	case <-time.After(100 * time.Millisecond):
	}
	require.Len(t, serverReceivedPackets, numPackets)
}

func TestDelayIncomingPackets(t *testing.T) {
	const numPackets = 3
	const delay = 200 * time.Millisecond
	serverAddr, serverReceivedPackets := runServer(t)
	var counter atomic.Int32
	clientConn := startProxy(t, &Opts{
		RemoteAddr: serverAddr.String(),
		// delay packet 1 by 200 ms
		// delay packet 2 by 400 ms
		// ...
		DelayPacket: func(d Direction, _ []byte) time.Duration {
			if d == DirectionOutgoing {
				return 0
			}
			p := counter.Add(1)
			return time.Duration(p) * delay
		},
	})

	start := time.Now()
	for i := 1; i <= numPackets; i++ {
		_, err := clientConn.Write(makePacket(t, protocol.PacketNumber(i), []byte("foobar"+strconv.Itoa(i))))
		require.NoError(t, err)
	}

	for i := 1; i <= numPackets; i++ {
		select {
		case data := <-serverReceivedPackets:
			require.WithinDuration(t, start.Add(time.Duration(i)*delay), time.Now(), delay/2)
			require.Equal(t, protocol.PacketNumber(i), readPacketNumber(t, data))
		case <-time.After(time.Second):
			t.Fatalf("timeout waiting for packet %d", i)
		}
	}
}

func TestPacketReordering(t *testing.T) {
	const delay = 200 * time.Millisecond
	expectDelay := func(startTime time.Time, numRTTs int) {
		expectedReceiveTime := startTime.Add(time.Duration(numRTTs) * delay)
		now := time.Now()
		require.True(t, now.After(expectedReceiveTime) || now.Equal(expectedReceiveTime))
		require.True(t, now.Before(expectedReceiveTime.Add(delay/2)))
	}

	serverAddr, serverReceivedPackets := runServer(t)
	var counter atomic.Int32
	clientConn := startProxy(t, &Opts{
		RemoteAddr: serverAddr.String(),
		// delay packet 1 by 600 ms
		// delay packet 2 by 400 ms
		// delay packet 3 by 200 ms
		DelayPacket: func(d Direction, _ []byte) time.Duration {
			if d == DirectionOutgoing {
				return 0
			}
			p := counter.Add(1)
			return 600*time.Millisecond - time.Duration(p-1)*delay
		},
	})

	// send 3 packets
	start := time.Now()
	for i := 1; i <= 3; i++ {
		_, err := clientConn.Write(makePacket(t, protocol.PacketNumber(i), []byte("foobar"+strconv.Itoa(i))))
		require.NoError(t, err)
	}
	for i := 1; i <= 3; i++ {
		select {
		case packet := <-serverReceivedPackets:
			expectDelay(start, i)
			expectedPacketNumber := protocol.PacketNumber(4 - i) // 3, 2, 1 in reverse order
			require.Equal(t, expectedPacketNumber, readPacketNumber(t, packet))
		case <-time.After(time.Second):
			t.Fatalf("timeout waiting for packet %d", i)
		}
	}
}

func TestConstantDelay(t *testing.T) { // no reordering expected here
	serverAddr, serverReceivedPackets := runServer(t)
	clientConn := startProxy(t, &Opts{
		RemoteAddr: serverAddr.String(),
		DelayPacket: func(d Direction, _ []byte) time.Duration {
			if d == DirectionOutgoing {
				return 0
			}
			return 100 * time.Millisecond
		},
	})

	// send 100 packets
	for i := 0; i < 100; i++ {
		_, err := clientConn.Write(makePacket(t, protocol.PacketNumber(i), []byte("foobar"+strconv.Itoa(i))))
		require.NoError(t, err)
	}
	require.Eventually(t, func() bool { return len(serverReceivedPackets) == 100 }, 5*time.Second, 10*time.Millisecond)
	timeout := time.After(5 * time.Second)
	for i := 0; i < 100; i++ {
		select {
		case packet := <-serverReceivedPackets:
			require.Equal(t, protocol.PacketNumber(i), readPacketNumber(t, packet))
		case <-timeout:
			t.Fatalf("timeout waiting for packet %d", i)
		}
	}
}

func TestDelayOutgoingPackets(t *testing.T) {
	const numPackets = 3
	const delay = 200 * time.Millisecond

	serverAddr, serverReceivedPackets := runServer(t)
	var counter atomic.Int32
	clientConn := startProxy(t, &Opts{
		RemoteAddr: serverAddr.String(),
		// delay packet 1 by 200 ms
		// delay packet 2 by 400 ms
		// ...
		DelayPacket: func(d Direction, _ []byte) time.Duration {
			if d == DirectionIncoming {
				return 0
			}
			p := counter.Add(1)
			return time.Duration(p) * delay
		},
	})

	clientReceivedPackets := make(chan packetData, numPackets)
	// receive the packets echoed by the server on client side
	go func() {
		for {
			buf := make([]byte, protocol.MaxPacketBufferSize)
			// the ReadFromUDP will error as soon as the UDP conn is closed
			n, _, err := clientConn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			clientReceivedPackets <- packetData(buf[0:n])
		}
	}()

	start := time.Now()
	for i := 1; i <= numPackets; i++ {
		_, err := clientConn.Write(makePacket(t, protocol.PacketNumber(i), []byte("foobar"+strconv.Itoa(i))))
		require.NoError(t, err)
	}
	// the packets should have arrived immediately at the server
	for i := 0; i < numPackets; i++ {
		select {
		case <-serverReceivedPackets:
		case <-time.After(time.Second):
			t.Fatalf("timeout")
		}
	}
	require.WithinDuration(t, start, time.Now(), delay/2)

	for i := 1; i <= numPackets; i++ {
		select {
		case packet := <-clientReceivedPackets:
			require.Equal(t, protocol.PacketNumber(i), readPacketNumber(t, packet))
			require.WithinDuration(t, start.Add(time.Duration(i)*delay), time.Now(), delay/2)
		case <-time.After(time.Second):
			t.Fatalf("timeout waiting for packet %d", i)
		}
	}
}
