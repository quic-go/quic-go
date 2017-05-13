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
		token, err := stkGen.NewToken(ip)
		Expect(err).ToNot(HaveOccurred())
		Expect(token).ToNot(BeEmpty())
	})

	It("accepts a valid STK", func() {
		ip := net.IPv4(192, 168, 0, 1)
		token, err := stkGen.NewToken(ip)
		Expect(err).ToNot(HaveOccurred())
		t, err := stkGen.VerifyToken(ip, token)
		Expect(err).ToNot(HaveOccurred())
		Expect(t).To(BeTemporally("~", time.Now(), time.Second))
	})

	It("rejects an STK for the wrong address", func() {
		ip := net.ParseIP("1.2.3.4")
		otherIP := net.ParseIP("4.3.2.1")
		token, err := stkGen.NewToken(ip)
		Expect(err).NotTo(HaveOccurred())
		_, err = stkGen.VerifyToken(otherIP, token)
		Expect(err).To(MatchError("invalid source address in STK"))
	})
})
