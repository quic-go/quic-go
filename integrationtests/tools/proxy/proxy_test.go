package quicproxy

import (
	"net"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/wire"

	"github.com/stretchr/testify/require"
)

func TestPacketQueue(t *testing.T) {
	q := newQueue()

	getPackets := func() []string {
		packets := make([]string, 0, len(q.Packets))
		for _, p := range q.Packets {
			packets = append(packets, string(p.Raw))
		}
		return packets
	}

	require.Empty(t, getPackets())
	now := time.Now()

	q.Add(packetEntry{Time: now, Raw: []byte("p3")})
	require.Equal(t, []string{"p3"}, getPackets())
	q.Add(packetEntry{Time: now.Add(time.Second), Raw: []byte("p4")})
	require.Equal(t, []string{"p3", "p4"}, getPackets())
	q.Add(packetEntry{Time: now.Add(-time.Second), Raw: []byte("p1")})
	require.Equal(t, []string{"p1", "p3", "p4"}, getPackets())
	q.Add(packetEntry{Time: now.Add(time.Second), Raw: []byte("p5")})
	require.Equal(t, []string{"p1", "p3", "p4", "p5"}, getPackets())
	q.Add(packetEntry{Time: now.Add(-time.Second), Raw: []byte("p2")})
	require.Equal(t, []string{"p1", "p2", "p3", "p4", "p5"}, getPackets())
}

func newUPDConnLocalhost(t testing.TB) *net.UDPConn {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })
	return conn
}

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

// Set up a dumb UDP server.
// In production this would be a QUIC server.
func runServer(t *testing.T) (*net.UDPAddr, chan []byte) {
	serverConn := newUPDConnLocalhost(t)

	serverReceivedPackets := make(chan []byte, 100)
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
			serverReceivedPackets <- buf[:n]
			// echo the packet
			if _, err := serverConn.WriteToUDP(buf[:n], addr); err != nil {
				return
			}
		}
	}()

	t.Cleanup(func() {
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatalf("timeout")
		}
	})

	return serverConn.LocalAddr().(*net.UDPAddr), serverReceivedPackets
}

func TestProxyingBackAndForth(t *testing.T) {
	serverAddr, _ := runServer(t)
	proxy := Proxy{
		Conn:       newUPDConnLocalhost(t),
		ServerAddr: serverAddr,
	}
	require.NoError(t, proxy.Start())
	defer proxy.Close()
	clientConn, err := net.DialUDP("udp", nil, proxy.LocalAddr().(*net.UDPAddr))
	require.NoError(t, err)

	// send the first packet
	_, err = clientConn.Write(makePacket(t, 1, []byte("foobar")))
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
	var fromAddr, toAddr atomic.Pointer[net.Addr]
	proxy := Proxy{
		Conn:       newUPDConnLocalhost(t),
		ServerAddr: serverAddr,
		DropPacket: func(d Direction, from, to net.Addr, _ []byte) bool {
			if d != DirectionIncoming {
				return false
			}
			fromAddr.Store(&from)
			toAddr.Store(&to)
			return counter.Add(1)%2 == 1
		},
	}
	require.NoError(t, proxy.Start())
	defer proxy.Close()
	clientConn, err := net.DialUDP("udp", nil, proxy.LocalAddr().(*net.UDPAddr))
	require.NoError(t, err)

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

	require.Equal(t, *fromAddr.Load(), clientConn.LocalAddr())
	require.Equal(t, *toAddr.Load(), serverAddr)
}

func TestDropOutgoingPackets(t *testing.T) {
	const numPackets = 6
	serverAddr, serverReceivedPackets := runServer(t)
	var counter atomic.Int32
	var fromAddr, toAddr atomic.Pointer[net.Addr]
	proxy := Proxy{
		Conn:       newUPDConnLocalhost(t),
		ServerAddr: serverAddr,
		DropPacket: func(d Direction, from, to net.Addr, _ []byte) bool {
			if d != DirectionOutgoing {
				return false
			}
			fromAddr.Store(&from)
			toAddr.Store(&to)
			return counter.Add(1)%2 == 1
		},
	}
	require.NoError(t, proxy.Start())
	defer proxy.Close()
	clientConn, err := net.DialUDP("udp", nil, proxy.LocalAddr().(*net.UDPAddr))
	require.NoError(t, err)

	clientReceivedPackets := make(chan struct{}, numPackets)
	// receive the packets echoed by the server on client side
	go func() {
		for {
			buf := make([]byte, protocol.MaxPacketBufferSize)
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

	require.Equal(t, *fromAddr.Load(), serverAddr)
	require.Equal(t, *toAddr.Load(), clientConn.LocalAddr())
}

func TestDelayIncomingPackets(t *testing.T) {
	const numPackets = 3
	const delay = 200 * time.Millisecond
	serverAddr, serverReceivedPackets := runServer(t)
	var counter atomic.Int32
	proxy := Proxy{
		Conn:       newUPDConnLocalhost(t),
		ServerAddr: serverAddr,
		DelayPacket: func(d Direction, _, _ net.Addr, _ []byte) time.Duration {
			// delay packet 1 by 200 ms
			// delay packet 2 by 400 ms
			// ...
			if d == DirectionOutgoing {
				return 0
			}
			p := counter.Add(1)
			return time.Duration(p) * delay
		},
	}
	require.NoError(t, proxy.Start())
	defer proxy.Close()
	clientConn, err := net.DialUDP("udp", nil, proxy.LocalAddr().(*net.UDPAddr))
	require.NoError(t, err)

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
	proxy := Proxy{
		Conn:       newUPDConnLocalhost(t),
		ServerAddr: serverAddr,
		DelayPacket: func(d Direction, _, _ net.Addr, _ []byte) time.Duration {
			// delay packet 1 by 600 ms
			// delay packet 2 by 400 ms
			// delay packet 3 by 200 ms
			if d == DirectionOutgoing {
				return 0
			}
			p := counter.Add(1)
			return 600*time.Millisecond - time.Duration(p-1)*delay
		},
	}
	require.NoError(t, proxy.Start())
	defer proxy.Close()
	clientConn, err := net.DialUDP("udp", nil, proxy.LocalAddr().(*net.UDPAddr))
	require.NoError(t, err)

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
	proxy := Proxy{
		Conn:       newUPDConnLocalhost(t),
		ServerAddr: serverAddr,
		DelayPacket: func(d Direction, _, _ net.Addr, _ []byte) time.Duration {
			if d == DirectionOutgoing {
				return 0
			}
			return 100 * time.Millisecond
		},
	}
	require.NoError(t, proxy.Start())
	defer proxy.Close()
	clientConn, err := net.DialUDP("udp", nil, proxy.LocalAddr().(*net.UDPAddr))
	require.NoError(t, err)

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
	proxy := Proxy{
		Conn:       newUPDConnLocalhost(t),
		ServerAddr: serverAddr,
		DelayPacket: func(d Direction, _, _ net.Addr, _ []byte) time.Duration {
			// delay packet 1 by 200 ms
			// delay packet 2 by 400 ms
			// ...
			if d == DirectionIncoming {
				return 0
			}
			p := counter.Add(1)
			return time.Duration(p) * delay
		},
	}
	require.NoError(t, proxy.Start())
	defer proxy.Close()
	clientConn, err := net.DialUDP("udp", nil, proxy.LocalAddr().(*net.UDPAddr))
	require.NoError(t, err)

	clientReceivedPackets := make(chan []byte, numPackets)
	// receive the packets echoed by the server on client side
	go func() {
		for {
			buf := make([]byte, protocol.MaxPacketBufferSize)
			n, _, err := clientConn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			clientReceivedPackets <- buf[:n]
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

func TestProxySwitchConn(t *testing.T) {
	serverConn := newUPDConnLocalhost(t)

	type packet struct {
		Data []byte
		Addr *net.UDPAddr
	}

	serverReceivedPackets := make(chan packet, 1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			buf := make([]byte, 1000)
			n, addr, err := serverConn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			serverReceivedPackets <- packet{Data: buf[:n], Addr: addr}
		}
	}()

	proxy := Proxy{
		Conn:       newUPDConnLocalhost(t),
		ServerAddr: serverConn.LocalAddr().(*net.UDPAddr),
	}
	require.NoError(t, proxy.Start())
	defer proxy.Close()

	clientConn := newUPDConnLocalhost(t)
	_, err := clientConn.WriteToUDP([]byte("hello"), proxy.LocalAddr().(*net.UDPAddr))
	require.NoError(t, err)
	clientConn.SetReadDeadline(time.Now().Add(time.Second))

	var firstConnAddr *net.UDPAddr
	select {
	case p := <-serverReceivedPackets:
		require.Equal(t, "hello", string(p.Data))
		require.NotEqual(t, clientConn.LocalAddr(), p.Addr)
		firstConnAddr = p.Addr
	case <-time.After(time.Second):
		t.Fatalf("timeout")
	}

	_, err = serverConn.WriteToUDP([]byte("hi"), firstConnAddr)
	require.NoError(t, err)
	buf := make([]byte, 1000)
	n, addr, err := clientConn.ReadFromUDP(buf)
	require.NoError(t, err)
	require.Equal(t, "hi", string(buf[:n]))
	require.Equal(t, proxy.LocalAddr(), addr)

	newConn := newUPDConnLocalhost(t)
	require.NoError(t, proxy.SwitchConn(clientConn.LocalAddr().(*net.UDPAddr), newConn))

	_, err = clientConn.WriteToUDP([]byte("foobar"), proxy.LocalAddr().(*net.UDPAddr))
	require.NoError(t, err)

	select {
	case p := <-serverReceivedPackets:
		require.Equal(t, "foobar", string(p.Data))
		require.NotEqual(t, clientConn.LocalAddr(), p.Addr)
		require.NotEqual(t, firstConnAddr, p.Addr)
		require.Equal(t, newConn.LocalAddr(), p.Addr)
	case <-time.After(time.Second):
		t.Fatalf("timeout")
	}

	// the old connection doesn't deliver any packets to the client anymore
	_, err = serverConn.WriteTo([]byte("invalid"), firstConnAddr)
	require.NoError(t, err)
	_, err = serverConn.WriteTo([]byte("foobaz"), newConn.LocalAddr())
	require.NoError(t, err)
	n, addr, err = clientConn.ReadFromUDP(buf)
	require.NoError(t, err)
	require.Equal(t, "foobaz", string(buf[:n])) // "invalid" is not delivered
	require.Equal(t, proxy.LocalAddr(), addr)
}
