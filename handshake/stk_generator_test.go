package handshake

import (
	"net"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("STK Generator", func() {
	var stkGen *STKGenerator

	BeforeEach(func() {
		var err error
		stkGen, err = NewSTKGenerator()
		Expect(err).ToNot(HaveOccurred())
	})

	It("generates an STK", func() {
		ip := net.IPv4(127, 0, 0, 1)
		token, err := stkGen.NewToken(&net.UDPAddr{IP: ip, Port: 1337})
		Expect(err).ToNot(HaveOccurred())
		Expect(token).ToNot(BeEmpty())
	})

	It("accepts a valid STK", func() {
		raddr := &net.UDPAddr{IP: net.IPv4(192, 168, 0, 1), Port: 1337}
		token, err := stkGen.NewToken(raddr)
		Expect(err).ToNot(HaveOccurred())
		t, err := stkGen.VerifyToken(raddr, token)
		Expect(err).ToNot(HaveOccurred())
		Expect(t).To(BeTemporally("~", time.Now(), time.Second))
	})

	It("works with an IPv6 address", func() {
		ip := net.ParseIP("2001:db8::68")
		Expect(ip).ToNot(BeNil())
		raddr := &net.UDPAddr{IP: ip, Port: 1337}
		token, err := stkGen.NewToken(raddr)
		Expect(err).ToNot(HaveOccurred())
		t, err := stkGen.VerifyToken(raddr, token)
		Expect(err).ToNot(HaveOccurred())
		Expect(t).To(BeTemporally("~", time.Now(), time.Second))
	})

	It("does not care about the port", func() {
		ip := net.IPv4(192, 168, 0, 1)
		token, err := stkGen.NewToken(&net.UDPAddr{IP: ip, Port: 1337})
		Expect(err).ToNot(HaveOccurred())
		_, err = stkGen.VerifyToken(&net.UDPAddr{IP: ip, Port: 7331}, token)
		Expect(err).ToNot(HaveOccurred())
	})

	It("rejects an STK for the wrong address", func() {
		ip := net.ParseIP("1.2.3.4")
		otherIP := net.ParseIP("4.3.2.1")
		token, err := stkGen.NewToken(&net.UDPAddr{IP: ip, Port: 1337})
		Expect(err).NotTo(HaveOccurred())
		_, err = stkGen.VerifyToken(&net.UDPAddr{IP: otherIP, Port: 1337}, token)
		Expect(err).To(MatchError("invalid source address in STK"))
	})

	It("works with an address that is not a UDP address", func() {
		raddr := &net.TCPAddr{IP: net.IPv4(192, 168, 0, 1), Port: 1337}
		token, err := stkGen.NewToken(raddr)
		Expect(err).ToNot(HaveOccurred())
		t, err := stkGen.VerifyToken(raddr, token)
		Expect(err).ToNot(HaveOccurred())
		Expect(t).To(BeTemporally("~", time.Now(), time.Second))
	})

	It("uses the string representation of an address that is not a UDP address", func() {
		// when using the string representation, the port matters
		ip := net.IPv4(192, 168, 0, 1)
		token, err := stkGen.NewToken(&net.TCPAddr{IP: ip, Port: 1337})
		Expect(err).ToNot(HaveOccurred())
		_, err = stkGen.VerifyToken(&net.TCPAddr{IP: ip, Port: 7331}, token)
		Expect(err).To(MatchError("invalid source address in STK"))
	})
})
