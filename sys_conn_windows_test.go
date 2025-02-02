//go:build windows

package quic

import (
	"fmt"
	"net"
	"testing"
	"time"

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

type oobRecordingConn struct {
	*net.UDPConn
	oobs [][]byte
}

func (c *oobRecordingConn) WriteMsgUDP(b, oob []byte, addr *net.UDPAddr) (n, oobn int, err error) {
	c.oobs = append(c.oobs, oob)
	return c.UDPConn.WriteMsgUDP(b, oob, addr)
}

func TestSysConnSendGSO(t *testing.T) {
	// if !platformSupportsGSO {
	// 	t.Skip("GSO not supported on this platform")
	// }

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
	fmt.Println(c.oobs, oob)
	require.Equal(t, cap(oob), cap(oobMsg)) // check that it appended to oob

	expected := appendUDPSegmentSizeMsg([]byte{}, 3)
	// Check that the first control message is the OOB control message.
	require.Equal(t, expected, oobMsg[:len(expected)])
}
