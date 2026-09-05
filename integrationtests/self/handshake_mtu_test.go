package self_test

import (
	"context"
	"fmt"
	"net"
	"os"
	"runtime"
	"sync/atomic"
	"syscall"
	"testing"
	"testing/synctest"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/wire"
	"github.com/quic-go/quic-go/testutils/simnet"

	"github.com/stretchr/testify/require"
)

type mtuLimitedPacketConn struct {
	net.PacketConn
	limit    int
	rejected atomic.Int32
}

func (c *mtuLimitedPacketConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	if len(b) > c.limit {
		c.rejected.Add(1)
		return 0, sendMessageTooLargeError(addr)
	}
	return c.PacketConn.WriteTo(b, addr)
}

func TestHandshakeWithSendMessageTooLarge(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" && runtime.GOOS != "windows" {
		t.Skip("send message size errors are not recognized on this platform")
	}
	for _, dir := range []direction{directionToServer, directionToClient, directionBoth} {
		for _, clientSpeaksFirst := range []bool{true, false} {
			t.Run(fmt.Sprintf("%s/client speaks first: %t", dir, clientSpeaksFirst), func(t *testing.T) {
				synctest.Test(t, func(t *testing.T) {
					n := &simnet.Simnet{Router: &simnet.PerfectRouter{}}
					settings := simnet.NodeBiDiLinkSettings{Latency: 10 * time.Millisecond}
					client := &mtuLimitedPacketConn{PacketConn: n.NewEndpoint(&net.UDPAddr{IP: net.IPv4(1, 0, 0, 1), Port: 9001}, settings), limit: protocol.MaxPacketBufferSize}
					server := &mtuLimitedPacketConn{PacketConn: n.NewEndpoint(&net.UDPAddr{IP: net.IPv4(1, 0, 0, 2), Port: 9002}, settings), limit: protocol.MaxPacketBufferSize}
					defer client.Close()
					defer server.Close()
					if dir == directionToServer || dir == directionBoth {
						client.limit = protocol.MinInitialPacketSize
					}
					if dir == directionToClient || dir == directionBoth {
						server.limit = protocol.MinInitialPacketSize
					}
					require.NoError(t, n.Start())
					defer n.Close()
					tr := &quic.Transport{Conn: server}
					defer tr.Close()
					ln, err := tr.Listen(getTLSConfig(), getQuicConfig(&quic.Config{DisablePathMTUDiscovery: true}))
					require.NoError(t, err)
					defer ln.Close()
					fn := dropTestProtocolClientSpeaksFirst
					if !clientSpeaksFirst {
						fn = dropTestProtocolServerSpeaksFirst
					}
					fn(t, ln, client, getTLSClientConfig(), 5*time.Second, GeneratePRData(10000))
					if client.limit == protocol.MinInitialPacketSize {
						require.Positive(t, client.rejected.Load())
					}
					if server.limit == protocol.MinInitialPacketSize {
						require.Positive(t, server.rejected.Load())
					}
				})
			})
		}
	}
}

func sendMessageTooLargeError(addr net.Addr) error {
	err := syscall.EMSGSIZE
	if runtime.GOOS == "windows" {
		err = syscall.Errno(10040) // WSAEMSGSIZE
	}
	return &net.OpError{Op: "write", Net: "udp", Addr: addr, Err: &os.SyscallError{Syscall: "sendmsg", Err: err}}
}

// Preserve the UDP socket capabilities so the integration test exercises both
// WriteMsgUDP errors during the handshake and real MTU probing afterwards.
type handshakeMTULimitedUDPConn struct {
	*net.UDPConn
	rejected atomic.Int32
}

func (c *handshakeMTULimitedUDPConn) WriteMsgUDP(b, oob []byte, addr *net.UDPAddr) (int, int, error) {
	if len(b) > protocol.MinInitialPacketSize && wire.IsLongHeaderPacket(b[0]) {
		c.rejected.Add(1)
		return 0, 0, sendMessageTooLargeError(addr)
	}
	return c.UDPConn.WriteMsgUDP(b, oob, addr)
}

func TestHandshakeSendMessageTooLargeAtMinimum(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" && runtime.GOOS != "windows" {
		t.Skip("send message size errors are not recognized on this platform")
	}
	synctest.Test(t, func(t *testing.T) {
		router := &simnet.PerfectRouter{}
		client := &mtuLimitedPacketConn{
			PacketConn: simnet.NewSimConn(&net.UDPAddr{IP: net.IPv4(1, 0, 0, 1), Port: 9001}, router),
			limit:      protocol.MinInitialPacketSize - 1,
		}
		defer client.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, err := quic.Dial(ctx, client, &net.UDPAddr{IP: net.IPv4(1, 0, 0, 2), Port: 9002}, getTLSClientConfig(), getQuicConfig(&quic.Config{
			HandshakeIdleTimeout: 10 * time.Second,
		}))
		require.ErrorIs(t, err, context.DeadlineExceeded)
		// Retries at the minimum still follow the PTO timer, rather than spinning
		// or producing invalid Initial datagrams smaller than 1200 bytes.
		require.Greater(t, client.rejected.Load(), int32(1))
		require.Less(t, client.rejected.Load(), int32(30))
	})
}
