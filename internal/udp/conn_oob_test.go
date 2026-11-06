//go:build darwin || linux || freebsd

package udp

import (
	"fmt"
	"net"
	"net/netip"
	"os"
	"runtime"
	"testing"

	"golang.org/x/net/ipv4"

	"github.com/quic-go/quic-go/internal/protocol"

	"github.com/stretchr/testify/require"
)

func TestConnECNAndPacketInfo(t *testing.T) {
	for _, tc := range []struct {
		name    string
		network string
		ip      netip.Addr // the client's address
	}{
		{name: "IPv4", network: "udp4", ip: netip.MustParseAddr("127.0.0.1")},
		{name: "IPv6", network: "udp6", ip: netip.IPv6Loopback()},
		{name: "dual-stack, IPv4", network: "udp", ip: netip.MustParseAddr("127.0.0.1")},
		{name: "dual-stack, IPv6", network: "udp", ip: netip.IPv6Loopback()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// packet info is only enabled for sockets listening on the unspecified address
			server := listenUDP(t, tc.network, nil)
			client := listenUDP(t, "udp", tc.ip.AsSlice())
			require.True(t, server.Capabilities().ECN)
			serverAddr := netip.AddrPortFrom(tc.ip, uint16(server.LocalAddr().(*net.UDPAddr).Port))

			for _, ecn := range []protocol.ECN{protocol.ECNNon, protocol.ECT1, protocol.ECT0, protocol.ECNCE} {
				_, err := client.WritePacket([]byte("foobar"), net.UDPAddrFromAddrPort(serverAddr), nil, 0, ecn)
				require.NoError(t, err)
				p, err := server.ReadPacket()
				require.NoError(t, err)
				require.Equal(t, ecn, p.ECN)
				require.Equal(t, tc.ip, p.Info.Addr)

				// the reply is sent from the address the packet was received on
				_, err = server.WritePacket([]byte("raboof"), p.RemoteAddr, p.Info.OOB(), 0, ecn)
				require.NoError(t, err)
				p, err = client.ReadPacket()
				require.NoError(t, err)
				require.Equal(t, ecn, p.ECN)
				require.Equal(t, serverAddr, p.RemoteAddr.(*net.UDPAddr).AddrPort())
			}
		})
	}
}

// A reply must be sent from the address the client sent to,
// not from the address the kernel's route lookup would pick.
func TestConnPacketInfoSourceAddress(t *testing.T) {
	// Linux routes all of 127.0.0.0/8 to lo. Other OSes need an alias for 127.0.0.2.
	// CI sets it up, but developer machines usually don't have it, so we only run there on CI.
	if runtime.GOOS != "linux" && os.Getenv("CI") == "" {
		t.Skip("requires 127.0.0.2 on lo0, add it with: sudo ifconfig lo0 alias 127.0.0.2/32")
	}

	ip := netip.MustParseAddr("127.0.0.2")
	ln, err := net.ListenUDP("udp4", net.UDPAddrFromAddrPort(netip.AddrPortFrom(ip, 0)))
	require.NoError(t, err, "add the address with: ifconfig lo0 alias %s/32", ip)
	ln.Close()

	for _, tc := range []struct{ name, network string }{
		{name: "IPv4", network: "udp4"},
		{name: "dual-stack", network: "udp"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := listenUDP(t, tc.network, nil)
			client := listenUDP(t, "udp4", net.IPv4(127, 0, 0, 1))
			serverAddr := netip.AddrPortFrom(ip, uint16(server.LocalAddr().(*net.UDPAddr).Port))

			_, err := client.WritePacket([]byte("foobar"), net.UDPAddrFromAddrPort(serverAddr), nil, 0, protocol.ECNUnsupported)
			require.NoError(t, err)
			p, err := server.ReadPacket()
			require.NoError(t, err)
			require.Equal(t, ip, p.Info.Addr)

			_, err = server.WritePacket([]byte("raboof"), p.RemoteAddr, p.Info.OOB(), 0, protocol.ECNUnsupported)
			require.NoError(t, err)
			p, err = client.ReadPacket()
			require.NoError(t, err)
			require.Equal(t, serverAddr, p.RemoteAddr.(*net.UDPAddr).AddrPort())
		})
	}
}

type mockBatchConn struct {
	*net.UDPConn
	t          *testing.T
	numMsgRead int

	callCounter int
}

var _ batchConn = &mockBatchConn{}

func (c *mockBatchConn) ReadBatch(ms []ipv4.Message, _ int) (int, error) {
	require.Len(c.t, ms, batchSize)
	for i := range c.numMsgRead {
		require.Len(c.t, ms[i].Buffers, 1)
		require.Len(c.t, ms[i].Buffers[0], protocol.MaxPacketBufferSize)
		data := fmt.Appendf(nil, "message %d", c.callCounter*c.numMsgRead+i)
		ms[i].N = copy(ms[i].Buffers[0], data)
	}
	c.callCounter++
	return c.numMsgRead, nil
}

func TestReadsMultipleMessagesInOneBatch(t *testing.T) {
	bc := &mockBatchConn{UDPConn: newUDPConnLocalhost(t), t: t, numMsgRead: batchSize/2 + 1}

	conn, err := Wrap(bc)
	require.NoError(t, err)

	for i := range batchSize + 1 {
		p, err := conn.ReadPacket()
		require.NoError(t, err)
		require.Equal(t, fmt.Sprintf("message %d", i), string(p.Data))
		require.Same(t, &p.Buffer.Data[0], &p.Data[0])
		p.Buffer.Release()
	}
	require.Equal(t, 2, bc.callCounter)
}

func TestWrapWithoutNetConn(t *testing.T) {
	_, err := Wrap(struct{ OOBCapablePacketConn }{newUDPConnLocalhost(t)})
	require.EqualError(t, err, "quic: OOBCapablePacketConn must implement net.Conn or ReadBatch")
}
