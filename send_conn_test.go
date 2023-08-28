package quic

import (
	"net"
	"net/netip"

	"github.com/quic-go/quic-go/internal/utils"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"go.uber.org/mock/gomock"
)

// Only if appendUDPSegmentSizeMsg actually appends a message (and isn't only a stub implementation),
// GSO is actually supported on this platform.
var platformSupportsGSO = len(appendUDPSegmentSizeMsg([]byte{}, 1337)) > 0

type oobRecordingConn struct {
	*net.UDPConn
	oobs [][]byte
}

func (c *oobRecordingConn) WriteMsgUDP(b, oob []byte, addr *net.UDPAddr) (n, oobn int, err error) {
	c.oobs = append(c.oobs, oob)
	return c.UDPConn.WriteMsgUDP(b, oob, addr)
}

var _ = Describe("Connection (for sending packets)", func() {
	remoteAddr := &net.UDPAddr{IP: net.IPv4(192, 168, 100, 200), Port: 1337}

	It("gets the local and remote addresses", func() {
		localAddr := &net.UDPAddr{IP: net.IPv4(192, 168, 0, 1), Port: 1234}
		rawConn := NewMockRawConn(mockCtrl)
		rawConn.EXPECT().LocalAddr().Return(localAddr)
		c := newSendConn(rawConn, remoteAddr, packetInfo{}, utils.DefaultLogger)
		Expect(c.LocalAddr().String()).To(Equal("192.168.0.1:1234"))
		Expect(c.RemoteAddr().String()).To(Equal("192.168.100.200:1337"))
	})

	It("uses the local address from the packet info", func() {
		localAddr := &net.UDPAddr{IP: net.IPv4(192, 168, 0, 1), Port: 1234}
		rawConn := NewMockRawConn(mockCtrl)
		rawConn.EXPECT().LocalAddr().Return(localAddr)
		c := newSendConn(rawConn, remoteAddr, packetInfo{addr: netip.AddrFrom4([4]byte{127, 0, 0, 42})}, utils.DefaultLogger)
		Expect(c.LocalAddr().String()).To(Equal("127.0.0.42:1234"))
	})

	It("sets the OOB", func() {
		rawConn := NewMockRawConn(mockCtrl)
		rawConn.EXPECT().LocalAddr()
		rawConn.EXPECT().capabilities().AnyTimes()
		pi := packetInfo{addr: netip.IPv6Loopback()}
		Expect(pi.OOB()).ToNot(BeEmpty())
		c := newSendConn(rawConn, remoteAddr, pi, utils.DefaultLogger)
		rawConn.EXPECT().WritePacket([]byte("foobar"), remoteAddr, pi.OOB(), uint16(0))
		Expect(c.Write([]byte("foobar"), 0)).To(Succeed())
	})

	It("writes", func() {
		rawConn := NewMockRawConn(mockCtrl)
		rawConn.EXPECT().LocalAddr()
		rawConn.EXPECT().capabilities().AnyTimes()
		c := newSendConn(rawConn, remoteAddr, packetInfo{}, utils.DefaultLogger)
		rawConn.EXPECT().WritePacket([]byte("foobar"), remoteAddr, gomock.Any(), uint16(3))
		Expect(c.Write([]byte("foobar"), 3)).To(Succeed())
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

				oob := make([]byte, 0, 42)
				oobConn.WritePacket([]byte("foobar"), addr, oob, 3)
				Expect(c.oobs).To(HaveLen(1))
				oobMsg := c.oobs[0]
				Expect(oobMsg).ToNot(BeEmpty())
				Expect(oobMsg).To(HaveCap(cap(oob))) // check that it appended to oob
				expected := appendUDPSegmentSizeMsg([]byte{}, 3)
				Expect(oobMsg).To(Equal(expected))
			})
		})
	}
})
