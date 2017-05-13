package crypto

import (
	"math"
	"net"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Source Address Tokens", func() {
	It("should generate the encryption key", func() {
		Expect(deriveKey([]byte("TESTING"))).To(Equal([]byte{0xee, 0x71, 0x18, 0x9, 0xfd, 0xb8, 0x9a, 0x79, 0x19, 0xfc, 0x5e, 0x1a, 0x97, 0x20, 0xb2, 0x6}))
	})

	Context("tokens", func() {
		It("serializes", func() {
			ip := []byte{127, 0, 0, 1}
			token := &sourceAddressToken{data: ip, timestamp: 0xdeadbeef}
			Expect(token.serialize()).To(Equal([]byte{
				0xef, 0xbe, 0xad, 0xde, 0x00, 0x00, 0x00, 0x00,
				127, 0, 0, 1,
			}))
		})

		It("reads", func() {
			token, err := parseToken([]byte{
				0xef, 0xbe, 0xad, 0xde, 0x00, 0x00, 0x00, 0x00,
				127, 0, 0, 1,
			})
			Expect(err).NotTo(HaveOccurred())
			Expect(token.data).To(Equal([]byte{127, 0, 0, 1}))
			Expect(token.timestamp).To(Equal(uint64(0xdeadbeef)))
		})

		It("rejects tokens of wrong size", func() {
			_, err := parseToken(nil)
			Expect(err).To(MatchError("STK too short: 0"))
		})
	})

	Context("source", func() {
		var (
			source *stkSource
			ip4    net.IP
			ip6    net.IP
		)

		BeforeEach(func() {
			var err error

			ip4 = net.ParseIP("1.2.3.4")
			Expect(ip4).NotTo(BeEmpty())
			ip6 = net.ParseIP("2001:0db8:0000:0000:0000:ff00:0042:8329")
			Expect(ip6).NotTo(BeEmpty())

			sourceI, err := NewStkSource()
			source = sourceI.(*stkSource)
			Expect(err).NotTo(HaveOccurred())
		})

		It("generates new tokens", func() {
			token, err := source.NewToken(ip4)
			Expect(err).NotTo(HaveOccurred())
			Expect(token).ToNot(BeEmpty())
		})

		It("generates and verifies ipv4 tokens", func() {
			stk, err := source.NewToken(ip4)
			Expect(err).NotTo(HaveOccurred())
			Expect(stk).ToNot(BeEmpty())
			decodedIP, _, err := source.DecodeToken(stk)
			Expect(err).NotTo(HaveOccurred())
			Expect(decodedIP).To(BeEquivalentTo(ip4))
		})

		It("generates and verify ipv6 tokens", func() {
			stk, err := source.NewToken(ip6)
			Expect(err).NotTo(HaveOccurred())
			Expect(stk).ToNot(BeEmpty())
			decodedIP, _, err := source.DecodeToken(stk)
			Expect(err).NotTo(HaveOccurred())
			Expect(decodedIP).To(BeEquivalentTo(ip6))
		})

		It("rejects empty tokens", func() {
			_, _, err := source.DecodeToken([]byte{})
			Expect(err).To(MatchError("STK too short"))
		})

		It("rejects invalid tokens", func() {
			_, _, err := source.DecodeToken([]byte("foobar"))
			Expect(err).To(HaveOccurred())
		})

		It("rejects overflowing timestamps", func() {
			stk, err := encryptToken(source.aead, &sourceAddressToken{
				data:      ip4,
				timestamp: math.MaxUint64,
			})
			Expect(err).NotTo(HaveOccurred())
			_, _, err = source.DecodeToken(stk)
			Expect(err).To(MatchError("invalid timestamp"))
		})

		It("returns the timestamp encoded in the token", func() {
			timestamp := time.Now().Add(-time.Hour)
			stk, err := encryptToken(source.aead, &sourceAddressToken{
				data:      ip4,
				timestamp: uint64(timestamp.Unix()),
			})
			Expect(err).NotTo(HaveOccurred())
			_, t, err := source.DecodeToken(stk)
			Expect(err).ToNot(HaveOccurred())
			Expect(t).To(BeTemporally("~", timestamp, time.Second))
		})
	})
})
