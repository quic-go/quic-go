package udp

import (
	"net"
	"runtime"
	"syscall"
	"testing"
	"time"

	"github.com/quic-go/quic-go/internal/monotime"
	"github.com/quic-go/quic-go/internal/protocol"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Wrap sets the DF bit on IPv4 and IPv6 sockets on these platforms.
var platformSupportsDF = runtime.GOOS == "linux" || runtime.GOOS == "darwin" || runtime.GOOS == "windows"

func newUDPConnLocalhost(t testing.TB) *net.UDPConn {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })
	// fail the test instead of blocking it if a packet is lost
	require.NoError(t, conn.SetReadDeadline(time.Now().Add(5*time.Second)))
	return conn
}

func listenUDP(t *testing.T, network string, ip net.IP) Conn {
	t.Helper()
	c, err := net.ListenUDP(network, &net.UDPAddr{IP: ip})
	require.NoError(t, err)
	t.Cleanup(func() { c.Close() })
	// fail the test instead of blocking it if a packet is lost
	require.NoError(t, c.SetReadDeadline(time.Now().Add(5*time.Second)))
	conn, err := Wrap(c, protocol.MaxPacketBufferSize)
	require.NoError(t, err)
	return conn
}

func requireDelivery(t *testing.T, from, to Conn) {
	t.Helper()
	start := monotime.Now()
	_, err := from.WritePacket([]byte("foobar"), to.LocalAddr(), nil, 0, protocol.ECNUnsupported)
	require.NoError(t, err)
	p, err := to.ReadPacket()
	require.NoError(t, err)
	require.Equal(t, "foobar", string(p.Data))
	require.Same(t, &p.Buffer.Data[0], &p.Data[0])
	require.Equal(t, from.LocalAddr(), p.RemoteAddr)
	require.False(t, p.RcvTime.Before(start))
	p.Buffer.Release()
}

func TestWrapUDPConn(t *testing.T) {
	for _, tc := range []struct {
		name    string
		network string
		ip      net.IP
	}{
		{name: "IPv4", network: "udp4", ip: net.IPv4(127, 0, 0, 1)},
		{name: "IPv6", network: "udp6", ip: net.IPv6loopback},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := listenUDP(t, tc.network, tc.ip)
			client := listenUDP(t, tc.network, tc.ip)
			require.Equal(t, platformSupportsDF, server.Capabilities().DF)
			requireDelivery(t, client, server)
		})
	}
}

// packetConn is a net.PacketConn that allows setting the buffer sizes,
// but doesn't give access to the socket.
type packetConn struct {
	net.PacketConn
	ReadBuffer  int
	WriteBuffer int
}

func (c *packetConn) SetReadBuffer(n int) error {
	c.ReadBuffer = n
	return nil
}

func (c *packetConn) SetWriteBuffer(n int) error {
	c.WriteBuffer = n
	return nil
}

func TestWrapPacketConn(t *testing.T) {
	pc := &packetConn{PacketConn: newUDPConnLocalhost(t)}
	conn, err := Wrap(pc, protocol.MaxPacketBufferSize)
	require.NoError(t, err)
	require.Equal(t, desiredBufferSize, pc.ReadBuffer)
	require.Equal(t, desiredBufferSize, pc.WriteBuffer)
	require.Equal(t, Capabilities{}, conn.Capabilities())
	// a Conn is used as is
	wrapped, err := Wrap(conn.(net.PacketConn), protocol.MaxPacketBufferSize)
	require.NoError(t, err)
	require.Same(t, conn, wrapped)

	peer := listenUDP(t, "udp4", net.IPv4(127, 0, 0, 1))
	requireDelivery(t, peer, conn)
	requireDelivery(t, conn, peer)
}

type faultySyscallConn struct{ net.PacketConn }

var _ syscall.Conn = &faultySyscallConn{}

func (c *faultySyscallConn) SyscallConn() (syscall.RawConn, error) { return nil, assert.AnError }

func TestWrapSyscallConnError(t *testing.T) {
	_, err := Wrap(&faultySyscallConn{PacketConn: newUDPConnLocalhost(t)}, protocol.MaxPacketBufferSize)
	require.ErrorIs(t, err, assert.AnError)
}

func TestReadPacketMaxPacketSize(t *testing.T) {
	const maxPacketSize = 1232

	// uses batched reads on platforms that support it
	udpConn := newUDPConnLocalhost(t)
	conn, err := Wrap(udpConn, maxPacketSize)
	require.NoError(t, err)
	// reads packets one by one
	basic, err := Wrap(&packetConn{PacketConn: newUDPConnLocalhost(t)}, maxPacketSize)
	require.NoError(t, err)

	for _, c := range []Conn{conn, basic} {
		sender := newUDPConnLocalhost(t)
		_, err = sender.WriteTo(make([]byte, maxPacketSize), c.LocalAddr())
		require.NoError(t, err)
		p, err := c.ReadPacket()
		require.NoError(t, err)
		require.Len(t, p.Data, maxPacketSize)
		p.Buffer.Release()

		// Packets that exceed the limit are truncated. Windows returns an error instead.
		_, err = sender.WriteTo(make([]byte, maxPacketSize+1), c.LocalAddr())
		require.NoError(t, err)
		p, err = c.ReadPacket()
		if runtime.GOOS == "windows" {
			require.True(t, IsRecvMsgSizeErr(err))
			continue
		}
		require.NoError(t, err)
		require.Len(t, p.Data, maxPacketSize)
		p.Buffer.Release()
	}
}
