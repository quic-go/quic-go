//go:build !windows

package quic

import (
	"fmt"
	"net"
	"time"

	"golang.org/x/net/ipv4"
	"golang.org/x/sys/unix"

	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/utils"

	"github.com/golang/mock/gomock"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("OOB Conn Test", func() {
	runServer := func(network, address string) (*net.UDPConn, <-chan *receivedPacket) {
		addr, err := net.ResolveUDPAddr(network, address)
		Expect(err).ToNot(HaveOccurred())
		udpConn, err := net.ListenUDP(network, addr)
		Expect(err).ToNot(HaveOccurred())
		oobConn, err := newConn(udpConn)
		Expect(err).ToNot(HaveOccurred())

		packetChan := make(chan *receivedPacket)
		go func() {
			defer GinkgoRecover()
			for {
				p, err := oobConn.ReadPacket()
				if err != nil {
					return
				}
				packetChan <- p
			}
		}()

		return udpConn, packetChan
	}

	Context("ECN conn", func() {
		sendPacketWithECN := func(network string, addr *net.UDPAddr, setECN func(uintptr)) net.Addr {
			conn, err := net.DialUDP(network, nil, addr)
			ExpectWithOffset(1, err).ToNot(HaveOccurred())
			rawConn, err := conn.SyscallConn()
			ExpectWithOffset(1, err).ToNot(HaveOccurred())
			ExpectWithOffset(1, rawConn.Control(func(fd uintptr) {
				setECN(fd)
			})).To(Succeed())
			_, err = conn.Write([]byte("foobar"))
			ExpectWithOffset(1, err).ToNot(HaveOccurred())
			return conn.LocalAddr()
		}

		It("reads ECN flags on IPv4", func() {
			conn, packetChan := runServer("udp4", "localhost:0")
			defer conn.Close()

			sentFrom := sendPacketWithECN(
				"udp4",
				conn.LocalAddr().(*net.UDPAddr),
				func(fd uintptr) {
					Expect(unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_TOS, 2)).To(Succeed())
				},
			)

			var p *receivedPacket
			Eventually(packetChan).Should(Receive(&p))
			Expect(p.rcvTime).To(BeTemporally("~", time.Now(), scaleDuration(20*time.Millisecond)))
			Expect(p.data).To(Equal([]byte("foobar")))
			Expect(p.remoteAddr).To(Equal(sentFrom))
			Expect(p.ecn).To(Equal(protocol.ECT0))
		})

		It("reads ECN flags on IPv6", func() {
			conn, packetChan := runServer("udp6", "[::]:0")
			defer conn.Close()

			sentFrom := sendPacketWithECN(
				"udp6",
				conn.LocalAddr().(*net.UDPAddr),
				func(fd uintptr) {
					Expect(unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_TCLASS, 3)).To(Succeed())
				},
			)

			var p *receivedPacket
			Eventually(packetChan).Should(Receive(&p))
			Expect(p.rcvTime).To(BeTemporally("~", time.Now(), scaleDuration(20*time.Millisecond)))
			Expect(p.data).To(Equal([]byte("foobar")))
			Expect(p.remoteAddr).To(Equal(sentFrom))
			Expect(p.ecn).To(Equal(protocol.ECNCE))
		})

		It("reads ECN flags on a connection that supports both IPv4 and IPv6", func() {
			conn, packetChan := runServer("udp", "0.0.0.0:0")
			defer conn.Close()
			port := conn.LocalAddr().(*net.UDPAddr).Port

			// IPv4
			sendPacketWithECN(
				"udp4",
				&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port},
				func(fd uintptr) {
					Expect(unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_TOS, 3)).To(Succeed())
				},
			)

			var p *receivedPacket
			Eventually(packetChan).Should(Receive(&p))
			Expect(utils.IsIPv4(p.remoteAddr.(*net.UDPAddr).IP)).To(BeTrue())
			Expect(p.ecn).To(Equal(protocol.ECNCE))

			// IPv6
			sendPacketWithECN(
				"udp6",
				&net.UDPAddr{IP: net.IPv6loopback, Port: port},
				func(fd uintptr) {
					Expect(unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_TCLASS, 1)).To(Succeed())
				},
			)

			Eventually(packetChan).Should(Receive(&p))
			Expect(utils.IsIPv4(p.remoteAddr.(*net.UDPAddr).IP)).To(BeFalse())
			Expect(p.ecn).To(Equal(protocol.ECT1))
		})
	})

	Context("Packet Info conn", func() {
		sendPacket := func(network string, addr *net.UDPAddr) net.Addr {
			conn, err := net.DialUDP(network, nil, addr)
			ExpectWithOffset(1, err).ToNot(HaveOccurred())
			_, err = conn.Write([]byte("foobar"))
			ExpectWithOffset(1, err).ToNot(HaveOccurred())
			return conn.LocalAddr()
		}

		It("reads packet info on IPv4", func() {
			conn, packetChan := runServer("udp4", ":0")
			defer conn.Close()

			addr := conn.LocalAddr().(*net.UDPAddr)
			ip := net.ParseIP("127.0.0.1").To4()
			addr.IP = ip
			sentFrom := sendPacket("udp4", addr)

			var p *receivedPacket
			Eventually(packetChan).Should(Receive(&p))
			Expect(p.rcvTime).To(BeTemporally("~", time.Now(), scaleDuration(20*time.Millisecond)))
			Expect(p.data).To(Equal([]byte("foobar")))
			Expect(p.remoteAddr).To(Equal(sentFrom))
			Expect(p.info).To(Not(BeNil()))
			Expect(p.info.addr.To4()).To(Equal(ip))
		})

		It("reads packet info on IPv6", func() {
			conn, packetChan := runServer("udp6", ":0")
			defer conn.Close()

			addr := conn.LocalAddr().(*net.UDPAddr)
			ip := net.ParseIP("::1")
			addr.IP = ip
			sentFrom := sendPacket("udp6", addr)

			var p *receivedPacket
			Eventually(packetChan).Should(Receive(&p))
			Expect(p.rcvTime).To(BeTemporally("~", time.Now(), scaleDuration(20*time.Millisecond)))
			Expect(p.data).To(Equal([]byte("foobar")))
			Expect(p.remoteAddr).To(Equal(sentFrom))
			Expect(p.info).To(Not(BeNil()))
			Expect(p.info.addr).To(Equal(ip))
		})

		It("reads packet info on a connection that supports both IPv4 and IPv6", func() {
			conn, packetChan := runServer("udp", ":0")
			defer conn.Close()
			port := conn.LocalAddr().(*net.UDPAddr).Port

			// IPv4
			ip4 := net.ParseIP("127.0.0.1").To4()
			sendPacket("udp4", &net.UDPAddr{IP: ip4, Port: port})

			var p *receivedPacket
			Eventually(packetChan).Should(Receive(&p))
			Expect(utils.IsIPv4(p.remoteAddr.(*net.UDPAddr).IP)).To(BeTrue())
			Expect(p.info).To(Not(BeNil()))
			Expect(p.info.addr.To4()).To(Equal(ip4))

			// IPv6
			ip6 := net.ParseIP("::1")
			sendPacket("udp6", &net.UDPAddr{IP: net.IPv6loopback, Port: port})

			Eventually(packetChan).Should(Receive(&p))
			Expect(utils.IsIPv4(p.remoteAddr.(*net.UDPAddr).IP)).To(BeFalse())
			Expect(p.info).To(Not(BeNil()))
			Expect(p.info.addr).To(Equal(ip6))
		})
	})

	Context("Batch Reading", func() {
		var batchConn *MockBatchConn

		BeforeEach(func() {
			batchConn = NewMockBatchConn(mockCtrl)
		})

		It("reads multiple messages in one batch", func() {
			const numMsgRead = batchSize/2 + 1
			var counter int
			batchConn.EXPECT().ReadBatch(gomock.Any(), gomock.Any()).DoAndReturn(func(ms []ipv4.Message, flags int) (int, error) {
				Expect(ms).To(HaveLen(batchSize))
				for i := 0; i < numMsgRead; i++ {
					Expect(ms[i].Buffers).To(HaveLen(1))
					Expect(ms[i].Buffers[0]).To(HaveLen(int(protocol.MaxPacketBufferSize)))
					data := []byte(fmt.Sprintf("message %d", counter))
					counter++
					ms[i].Buffers[0] = data
					ms[i].N = len(data)
				}
				return numMsgRead, nil
			}).Times(2)

			addr, err := net.ResolveUDPAddr("udp", "localhost:0")
			Expect(err).ToNot(HaveOccurred())
			udpConn, err := net.ListenUDP("udp", addr)
			Expect(err).ToNot(HaveOccurred())
			oobConn, err := newConn(udpConn)
			Expect(err).ToNot(HaveOccurred())
			oobConn.batchConn = batchConn

			for i := 0; i < batchSize+1; i++ {
				p, err := oobConn.ReadPacket()
				Expect(err).ToNot(HaveOccurred())
				Expect(string(p.data)).To(Equal(fmt.Sprintf("message %d", i)))
			}
		})
	})
})
