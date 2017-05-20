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

	It("works with nil tokens", func() {
		stk, err := stkGen.DecodeToken(nil)
		Expect(err).ToNot(HaveOccurred())
		Expect(stk).To(BeNil())
	})

	It("accepts a valid STK", func() {
		ip := net.IPv4(192, 168, 0, 1)
		token, err := stkGen.NewToken(&net.UDPAddr{IP: ip, Port: 1337})
		Expect(err).ToNot(HaveOccurred())
		stk, err := stkGen.DecodeToken(token)
		Expect(err).ToNot(HaveOccurred())
		Expect(stk.RemoteAddr).To(Equal("192.168.0.1"))
		Expect(stk.SentTime).To(BeTemporally("~", time.Now(), time.Second))
	})

	It("works with an IPv6 addresses ", func() {
		addresses := []string{
			"2001:db8::68",
			"2001:0000:4136:e378:8000:63bf:3fff:fdd2",
			"2001::1",
			"ff01:0:0:0:0:0:0:2",
		}
		for _, addr := range addresses {
			ip := net.ParseIP(addr)
			Expect(ip).ToNot(BeNil())
			raddr := &net.UDPAddr{IP: ip, Port: 1337}
			token, err := stkGen.NewToken(raddr)
			Expect(err).ToNot(HaveOccurred())
			stk, err := stkGen.DecodeToken(token)
			Expect(err).ToNot(HaveOccurred())
			Expect(stk.RemoteAddr).To(Equal(ip.String()))
			Expect(stk.SentTime).To(BeTemporally("~", time.Now(), time.Second))
		}
	})

	It("uses the string representation an address that is not a UDP address", func() {
		raddr := &net.TCPAddr{IP: net.IPv4(192, 168, 13, 37), Port: 1337}
		token, err := stkGen.NewToken(raddr)
		Expect(err).ToNot(HaveOccurred())
		stk, err := stkGen.DecodeToken(token)
		Expect(err).ToNot(HaveOccurred())
		Expect(stk.RemoteAddr).To(Equal("192.168.13.37:1337"))
		Expect(stk.SentTime).To(BeTemporally("~", time.Now(), time.Second))
	})
})
