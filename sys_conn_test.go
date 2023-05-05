package quic

import (
	"net"
	"runtime"
	"time"

	"github.com/quic-go/quic-go/internal/protocol"

	"github.com/golang/mock/gomock"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Basic Conn Test", func() {
	It("reads a packet", func() {
		c := NewMockPacketConn(mockCtrl)
		addr := &net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 1234}
		c.EXPECT().ReadFrom(gomock.Any()).DoAndReturn(func(b []byte) (int, net.Addr, error) {
			data := []byte("foobar")
			Expect(b).To(HaveLen(int(protocol.MaxPacketBufferSize)))
			return copy(b, data), addr, nil
		})

		conn, err := wrapConn(c)
		Expect(err).ToNot(HaveOccurred())
		p, err := conn.ReadPacket()
		Expect(err).ToNot(HaveOccurred())
		Expect(p.data).To(Equal([]byte("foobar")))
		Expect(p.rcvTime).To(BeTemporally("~", time.Now(), scaleDuration(100*time.Millisecond)))
		Expect(p.remoteAddr).To(Equal(addr))
	})
})

var _ = Describe("Can change the receive buffer size", func() {
	It("Force a change (if we have CAP_NET_ADMIN)", func() {
		if runtime.GOOS != "linux" {
			return // Only an option on linux
		}
		c, err := net.ListenPacket("udp", "127.0.0.1:0")
		Expect(err).ToNot(HaveOccurred())
		forceSetReceiveBuffer(c, 2048)
		size, err := inspectReadBuffer(c)
		Expect(err).ToNot(HaveOccurred())
		Expect(size).To(Equal(2048))

		forceSetReceiveBuffer(c, 4096)
		size, err = inspectReadBuffer(c)
		Expect(err).ToNot(HaveOccurred())
		Expect(size).To(Equal(4096))
	})
})
