//go:build darwin || linux || freebsd

package quic

import (
	"fmt"
	"net"
	"testing"
	"time"

	"golang.org/x/net/ipv4"
	"golang.org/x/sys/unix"

	"github.com/quic-go/quic-go/internal/protocol"

	"github.com/stretchr/testify/require"
)

func isIPv4(ip net.IP) bool { return ip.To4() != nil }

func runSysConnServer(t *testing.T, network string, addr *net.UDPAddr) (*net.UDPAddr, <-chan receivedPacket) {
	t.Helper()
	udpConn, err := net.ListenUDP(network, addr)
	require.NoError(t, err)
	t.Cleanup(func() { udpConn.Close() })

	oobConn, err := newConn(udpConn, true)
	require.NoError(t, err)
	require.True(t, oobConn.capabilities().DF)

	packetChan := make(chan receivedPacket, 1)
	go func() {
		for {
			p, err := oobConn.ReadPacket()
			if err != nil {
				return
			}
			packetChan <- p
		}
	}()
	return udpConn.LocalAddr().(*net.UDPAddr), packetChan
}

// sendUDPPacketWithECN opens a new UDP socket and sends one packet with the ECN set.
// It returns the local address of the socket.
func sendUDPPacketWithECN(t *testing.T, network string, addr *net.UDPAddr, setECN func(uintptr)) net.Addr {
	conn, err := net.DialUDP(network, nil, addr)
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })

	rawConn, err := conn.SyscallConn()
	require.NoError(t, err)
	require.NoError(t, rawConn.Control(func(fd uintptr) { setECN(fd) }))
	_, err = conn.Write([]byte("foobar"))
	require.NoError(t, err)
	return conn.LocalAddr()
}

func TestReadECNFlagsIPv4(t *testing.T) {
	addr, packetChan := runSysConnServer(t, "udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})

	sentFrom := sendUDPPacketWithECN(t,
		"udp4",
		addr,
		func(fd uintptr) {
			require.NoError(t, unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_TOS, 2))
		},
	)

	select {
	case p := <-packetChan:
		require.WithinDuration(t, time.Now(), p.rcvTime, scaleDuration(20*time.Millisecond))
		require.Equal(t, []byte("foobar"), p.data)
		require.Equal(t, sentFrom, p.remoteAddr)
		require.Equal(t, protocol.ECT0, p.ecn)
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for packet")
	}
}

func TestReadECNFlagsIPv6(t *testing.T) {
	addr, packetChan := runSysConnServer(t, "udp6", &net.UDPAddr{IP: net.IPv6loopback, Port: 0})

	sentFrom := sendUDPPacketWithECN(t,
		"udp6",
		addr,
		func(fd uintptr) {
			require.NoError(t, unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_TCLASS, 3))
		},
	)

	select {
	case p := <-packetChan:
		require.WithinDuration(t, time.Now(), p.rcvTime, scaleDuration(20*time.Millisecond))
		require.Equal(t, []byte("foobar"), p.data)
		require.Equal(t, sentFrom, p.remoteAddr)
		require.Equal(t, protocol.ECNCE, p.ecn)
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for packet")
	}
}

func TestReadECNFlagsDualStack(t *testing.T) {
	addr, packetChan := runSysConnServer(t, "udp", &net.UDPAddr{IP: net.IPv4(0, 0, 0, 0), Port: 0})

	// IPv4
	sentFrom := sendUDPPacketWithECN(t,
		"udp4",
		&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: addr.Port},
		func(fd uintptr) {
			require.NoError(t, unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_TOS, 3))
		},
	)

	select {
	case p := <-packetChan:
		require.True(t, isIPv4(p.remoteAddr.(*net.UDPAddr).IP))
		require.Equal(t, sentFrom.String(), p.remoteAddr.String())
		require.Equal(t, protocol.ECNCE, p.ecn)
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for packet")
	}

	// IPv6
	sentFrom = sendUDPPacketWithECN(t,
		"udp6",
		&net.UDPAddr{IP: net.IPv6loopback, Port: addr.Port},
		func(fd uintptr) {
			require.NoError(t, unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_TCLASS, 1))
		},
	)

	select {
	case p := <-packetChan:
		require.Equal(t, sentFrom, p.remoteAddr)
		require.False(t, isIPv4(p.remoteAddr.(*net.UDPAddr).IP))
		require.Equal(t, protocol.ECT1, p.ecn)
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for packet")
	}
}

func TestSendPacketsWithECNOnIPv4(t *testing.T) {
	addr, packetChan := runSysConnServer(t, "udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})

	c, err := net.ListenUDP("udp4", nil)
	require.NoError(t, err)
	defer c.Close()

	for _, val := range []protocol.ECN{protocol.ECNNon, protocol.ECT1, protocol.ECT0, protocol.ECNCE} {
		_, _, err = c.WriteMsgUDP([]byte("foobar"), appendIPv4ECNMsg([]byte{}, val), addr)
		require.NoError(t, err)
		select {
		case p := <-packetChan:
			require.Equal(t, []byte("foobar"), p.data)
			require.Equal(t, val, p.ecn)
		case <-time.After(time.Second):
			t.Fatal("timeout waiting for packet")
		}
	}
}

func TestSendPacketsWithECNOnIPv6(t *testing.T) {
	addr, packetChan := runSysConnServer(t, "udp6", &net.UDPAddr{IP: net.IPv6loopback, Port: 0})

	c, err := net.ListenUDP("udp6", nil)
	require.NoError(t, err)
	defer c.Close()

	for _, val := range []protocol.ECN{protocol.ECNNon, protocol.ECT1, protocol.ECT0, protocol.ECNCE} {
		_, _, err = c.WriteMsgUDP([]byte("foobar"), appendIPv6ECNMsg([]byte{}, val), addr)
		require.NoError(t, err)
		select {
		case p := <-packetChan:
			require.Equal(t, []byte("foobar"), p.data)
			require.Equal(t, val, p.ecn)
		case <-time.After(time.Second):
			t.Fatal("timeout waiting for packet")
		}
	}
}

func TestSysConnPacketInfoIPv4(t *testing.T) {
	// need to listen on 0.0.0.0, otherwise we won't get the packet info
	addr, packetChan := runSysConnServer(t, "udp4", &net.UDPAddr{IP: net.IPv4zero, Port: 0})

	conn, err := net.DialUDP("udp4", nil, addr)
	require.NoError(t, err)
	defer conn.Close()
	_, err = conn.Write([]byte("foobar"))
	require.NoError(t, err)

	select {
	case p := <-packetChan:
		require.WithinDuration(t, time.Now(), p.rcvTime, scaleDuration(50*time.Millisecond))
		require.Equal(t, []byte("foobar"), p.data)
		require.Equal(t, conn.LocalAddr(), p.remoteAddr)
		require.True(t, p.info.addr.IsValid())
		require.True(t, isIPv4(p.info.addr.AsSlice()))
		require.Equal(t, net.IPv4(127, 0, 0, 1).String(), p.info.addr.String())
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for packet")
	}
}

func TestSysConnPacketInfoIPv6(t *testing.T) {
	// need to listen on ::, otherwise we won't get the packet info
	addr, packetChan := runSysConnServer(t, "udp6", &net.UDPAddr{IP: net.IPv6zero, Port: 0})

	conn, err := net.DialUDP("udp6", nil, addr)
	require.NoError(t, err)
	defer conn.Close()
	_, err = conn.Write([]byte("foobar"))
	require.NoError(t, err)

	select {
	case p := <-packetChan:
		require.WithinDuration(t, time.Now(), p.rcvTime, scaleDuration(20*time.Millisecond))
		require.Equal(t, []byte("foobar"), p.data)
		require.Equal(t, conn.LocalAddr(), p.remoteAddr)
		require.NotNil(t, p.info)
		require.Equal(t, net.IPv6loopback, net.IP(p.info.addr.AsSlice()))
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for packet")
	}
}

func TestSysConnPacketInfoDualStack(t *testing.T) {
	addr, packetChan := runSysConnServer(t, "udp", &net.UDPAddr{})

	// IPv4
	conn4, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: addr.Port})
	require.NoError(t, err)
	defer conn4.Close()
	_, err = conn4.Write([]byte("foobar"))
	require.NoError(t, err)

	select {
	case p := <-packetChan:
		require.True(t, isIPv4(p.remoteAddr.(*net.UDPAddr).IP))
		require.NotNil(t, p.info)
		require.True(t, p.info.addr.Is4())
		require.Equal(t, net.IPv4(127, 0, 0, 1).String(), p.info.addr.String())
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for IPv4 packet")
	}

	// IPv6
	conn6, err := net.DialUDP("udp6", nil, addr)
	require.NoError(t, err)
	defer conn6.Close()
	_, err = conn6.Write([]byte("foobar"))
	require.NoError(t, err)

	select {
	case p := <-packetChan:
		require.False(t, isIPv4(p.remoteAddr.(*net.UDPAddr).IP))
		require.NotNil(t, p.info)
		require.Equal(t, net.IPv6loopback.String(), p.info.addr.String())
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for IPv6 packet")
	}
}

type oobRecordingConn struct {
	*net.UDPConn
	oobs [][]byte
}

func (c *oobRecordingConn) WriteMsgUDP(b, oob []byte, addr *net.UDPAddr) (n, oobn int, err error) {
	c.oobs = append(c.oobs, oob)
	return c.UDPConn.WriteMsgUDP(b, oob, addr)
}

type mockBatchConn struct {
	t          *testing.T
	numMsgRead int

	callCounter int
}

var _ batchConn = &mockBatchConn{}

func (c *mockBatchConn) ReadBatch(ms []ipv4.Message, _ int) (int, error) {
	require.Len(c.t, ms, batchSize)
	for i := 0; i < c.numMsgRead; i++ {
		require.Len(c.t, ms[i].Buffers, 1)
		require.Len(c.t, ms[i].Buffers[0], protocol.MaxPacketBufferSize)
		data := []byte(fmt.Sprintf("message %d", c.callCounter*c.numMsgRead+i))
		ms[i].Buffers[0] = data
		ms[i].N = len(data)
	}
	c.callCounter++
	return c.numMsgRead, nil
}

func TestReadsMultipleMessagesInOneBatch(t *testing.T) {
	bc := &mockBatchConn{t: t, numMsgRead: batchSize/2 + 1}

	udpConn := newUDPConnLocalhost(t)
	oobConn, err := newConn(udpConn, true)
	require.NoError(t, err)
	oobConn.batchConn = bc

	for i := 0; i < batchSize+1; i++ {
		p, err := oobConn.ReadPacket()
		require.NoError(t, err)
		require.Equal(t, fmt.Sprintf("message %d", i), string(p.data))
	}
	require.Equal(t, 2, bc.callCounter)
}

func TestSysConnSendGSO(t *testing.T) {
	if !platformSupportsGSO {
		t.Skip("GSO not supported on this platform")
	}

	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	require.NoError(t, err)
	c := &oobRecordingConn{UDPConn: udpConn}
	oobConn, err := newConn(c, true)
	require.NoError(t, err)
	require.True(t, oobConn.capabilities().GSO)

	oob := make([]byte, 0, 123)
	oobConn.WritePacket([]byte("foobar"), udpConn.LocalAddr(), oob, 3, protocol.ECNCE)
	require.Len(t, c.oobs, 1)
	oobMsg := c.oobs[0]
	require.NotEmpty(t, oobMsg)
	require.Equal(t, cap(oob), cap(oobMsg)) // check that it appended to oob
	expected := appendUDPSegmentSizeMsg([]byte{}, 3)
	// Check that the first control message is the OOB control message.
	require.Equal(t, expected, oobMsg[:len(expected)])
}
