package handshake

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Token Protector", func() {
	var tp tokenProtector

	BeforeEach(func() {
		var err error
		tp, err = newTokenProtector()
		Expect(err).ToNot(HaveOccurred())
	})

	It("encodes and decodes tokens", func() {
		token, err := tp.NewToken([]byte("foobar"))
		Expect(err).ToNot(HaveOccurred())
		Expect(token).ToNot(ContainSubstring("foobar"))
		decoded, err := tp.DecodeToken(token)
		Expect(err).ToNot(HaveOccurred())
		Expect(decoded).To(Equal([]byte("foobar")))
	})

	It("fails deconding invalid tokens", func() {
		token, err := tp.NewToken([]byte("foobar"))
		Expect(err).ToNot(HaveOccurred())
		token = token[1:] // remove the first byte
		_, err = tp.DecodeToken(token)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("message authentication failed"))
	})

	It("errors when decoding too short tokens", func() {
		_, err := tp.DecodeToken([]byte("foobar"))
		Expect(err).To(MatchError("token too short: 6"))
	})
})
