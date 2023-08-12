//go:build darwin || linux || freebsd

package quic

import (
	"fmt"
	"net"
	"time"

	"golang.org/x/net/ipv4"
	"golang.org/x/sys/unix"

	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/utils"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"go.uber.org/mock/gomock"
)

type oobRecordingConn struct {
	*net.UDPConn
	oobs [][]byte
}

func (c *oobRecordingConn) WriteMsgUDP(b, oob []byte, addr *net.UDPAddr) (n, oobn int, err error) {
	c.oobs = append(c.oobs, oob)
	return c.UDPConn.WriteMsgUDP(b, oob, addr)
}

var _ = Describe("OOB Conn Test", func() {
	runServer := func(network, address string) (*net.UDPConn, <-chan receivedPacket) {
		addr, err := net.ResolveUDPAddr(network, address)
		Expect(err).ToNot(HaveOccurred())
		udpConn, err := net.ListenUDP(network, addr)
		Expect(err).ToNot(HaveOccurred())
		oobConn, err := newConn(udpConn, true)
		Expect(err).ToNot(HaveOccurred())
		Expect(oobConn.capabilities().DF).To(BeTrue())

		packetChan := make(chan receivedPacket)
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

	Context("reading ECN-marked packets", func() {
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

			var p receivedPacket
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

			var p receivedPacket
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

			var p receivedPacket
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

		It("sends packets with ECN on IPv4", func() {
			conn, packetChan := runServer("udp4", "localhost:0")
			defer conn.Close()

			c, err := net.ListenUDP("udp4", nil)
			Expect(err).ToNot(HaveOccurred())
			defer c.Close()

			for _, val := range []protocol.ECN{protocol.ECNNon, protocol.ECT1, protocol.ECT0, protocol.ECNCE} {
				_, _, err = c.WriteMsgUDP([]byte("foobar"), appendIPv4ECNMsg([]byte{}, val), conn.LocalAddr().(*net.UDPAddr))
				Expect(err).ToNot(HaveOccurred())
				var p receivedPacket
				Eventually(packetChan).Should(Receive(&p))
				Expect(p.data).To(Equal([]byte("foobar")))
				Expect(p.ecn).To(Equal(val))
			}
		})

		It("sends packets with ECN on IPv6", func() {
			conn, packetChan := runServer("udp6", "[::1]:0")
			defer conn.Close()

			c, err := net.ListenUDP("udp6", nil)
			Expect(err).ToNot(HaveOccurred())
			defer c.Close()

			for _, val := range []protocol.ECN{protocol.ECNNon, protocol.ECT1, protocol.ECT0, protocol.ECNCE} {
				_, _, err = c.WriteMsgUDP([]byte("foobar"), appendIPv6ECNMsg([]byte{}, val), conn.LocalAddr().(*net.UDPAddr))
				Expect(err).ToNot(HaveOccurred())
				var p receivedPacket
				Eventually(packetChan).Should(Receive(&p))
				Expect(p.data).To(Equal([]byte("foobar")))
				Expect(p.ecn).To(Equal(val))
			}
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

			var p receivedPacket
			Eventually(packetChan).Should(Receive(&p))
			Expect(p.rcvTime).To(BeTemporally("~", time.Now(), scaleDuration(20*time.Millisecond)))
			Expect(p.data).To(Equal([]byte("foobar")))
			Expect(p.remoteAddr).To(Equal(sentFrom))
			Expect(p.info.addr.IsValid()).To(BeTrue())
			Expect(net.IP(p.info.addr.AsSlice())).To(Equal(ip))
		})

		It("reads packet info on IPv6", func() {
			conn, packetChan := runServer("udp6", ":0")
			defer conn.Close()

			addr := conn.LocalAddr().(*net.UDPAddr)
			ip := net.ParseIP("::1")
			addr.IP = ip
			sentFrom := sendPacket("udp6", addr)

			var p receivedPacket
			Eventually(packetChan).Should(Receive(&p))
			Expect(p.rcvTime).To(BeTemporally("~", time.Now(), scaleDuration(20*time.Millisecond)))
			Expect(p.data).To(Equal([]byte("foobar")))
			Expect(p.remoteAddr).To(Equal(sentFrom))
			Expect(p.info).To(Not(BeNil()))
			Expect(net.IP(p.info.addr.AsSlice())).To(Equal(ip))
		})

		It("reads packet info on a connection that supports both IPv4 and IPv6", func() {
			conn, packetChan := runServer("udp", ":0")
			defer conn.Close()
			port := conn.LocalAddr().(*net.UDPAddr).Port

			// IPv4
			ip4 := net.ParseIP("127.0.0.1")
			sendPacket("udp4", &net.UDPAddr{IP: ip4, Port: port})

			var p receivedPacket
			Eventually(packetChan).Should(Receive(&p))
			Expect(utils.IsIPv4(p.remoteAddr.(*net.UDPAddr).IP)).To(BeTrue())
			Expect(p.info).To(Not(BeNil()))
			Expect(p.info.addr.Is4In6() || p.info.addr.Is4()).To(BeTrue())
			ip := p.info.addr.As4()
			Expect(net.IP(ip[:])).To(Equal(ip4.To4()))

			// IPv6
			ip6 := net.ParseIP("::1")
			sendPacket("udp6", &net.UDPAddr{IP: net.IPv6loopback, Port: port})

			Eventually(packetChan).Should(Receive(&p))
			Expect(utils.IsIPv4(p.remoteAddr.(*net.UDPAddr).IP)).To(BeFalse())
			Expect(p.info).To(Not(BeNil()))
			Expect(net.IP(p.info.addr.AsSlice())).To(Equal(ip6))
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
					Expect(ms[i].Buffers[0]).To(HaveLen(protocol.MaxPacketBufferSize))
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
			oobConn, err := newConn(udpConn, true)
			Expect(err).ToNot(HaveOccurred())
			oobConn.batchConn = batchConn

			for i := 0; i < batchSize+1; i++ {
				p, err := oobConn.ReadPacket()
				Expect(err).ToNot(HaveOccurred())
				Expect(string(p.data)).To(Equal(fmt.Sprintf("message %d", i)))
			}
		})
	})

	Context("sending ECN-marked packets", func() {
		It("sets the ECN control message", func() {
			addr, err := net.ResolveUDPAddr("udp", "localhost:0")
			Expect(err).ToNot(HaveOccurred())
			udpConn, err := net.ListenUDP("udp", addr)
			Expect(err).ToNot(HaveOccurred())
			c := &oobRecordingConn{UDPConn: udpConn}
			oobConn, err := newConn(c, true)
			Expect(err).ToNot(HaveOccurred())

			oob := make([]byte, 0, 123)
			oobConn.WritePacket([]byte("foobar"), addr, oob, 0, protocol.ECNCE)
			Expect(c.oobs).To(HaveLen(1))
			oobMsg := c.oobs[0]
			Expect(oobMsg).ToNot(BeEmpty())
			Expect(oobMsg).To(HaveCap(cap(oob))) // check that it appended to oob
			expected := appendIPv4ECNMsg([]byte{}, protocol.ECNCE)
			Expect(oobMsg).To(Equal(expected))
		})
	})

	if platformSupportsGSO {
		Context("GSO", func() {
			It("appends the GSO control message", func() {
				addr, err := net.ResolveUDPAddr("udp", "localhost:0")
				Expect(err).ToNot(HaveOccurred())
				udpConn, err := net.ListenUDP("udp", addr)
				Expect(err).ToNot(HaveOccurred())
				c := &oobRecordingConn{UDPConn: udpConn}
				oobConn, err := newConn(c, true)
				Expect(err).ToNot(HaveOccurred())
				Expect(oobConn.capabilities().GSO).To(BeTrue())

				oob := make([]byte, 0, 123)
				oobConn.WritePacket([]byte("foobar"), addr, oob, 3, protocol.ECNCE)
				Expect(c.oobs).To(HaveLen(1))
				oobMsg := c.oobs[0]
				Expect(oobMsg).ToNot(BeEmpty())
				Expect(oobMsg).To(HaveCap(cap(oob))) // check that it appended to oob
				expected := appendUDPSegmentSizeMsg([]byte{}, 3)
				// Check that the first control message is the OOB control message.
				Expect(oobMsg[:len(expected)]).To(Equal(expected))
			})
		})
	}
})
