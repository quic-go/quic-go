package handshake

import (
	"crypto/rand"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Token Protector", func() {
	var tp tokenProtector

	BeforeEach(func() {
		var key TokenProtectorKey
		rand.Read(key[:])
		var err error
		tp = newTokenProtector(key)
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

	It("uses the different keys", func() {
		var key1, key2 TokenProtectorKey
		rand.Read(key1[:])
		rand.Read(key2[:])
		tp1 := newTokenProtector(key1)
		tp2 := newTokenProtector(key2)
		t1, err := tp1.NewToken([]byte("foo"))
		Expect(err).ToNot(HaveOccurred())
		t2, err := tp2.NewToken([]byte("foo"))
		Expect(err).ToNot(HaveOccurred())

		_, err = tp1.DecodeToken(t1)
		Expect(err).ToNot(HaveOccurred())
		_, err = tp1.DecodeToken(t2)
		Expect(err).To(HaveOccurred())

		// now create another token protector, reusing key1
		tp3 := newTokenProtector(key1)
		_, err = tp3.DecodeToken(t1)
		Expect(err).ToNot(HaveOccurred())
		_, err = tp3.DecodeToken(t2)
		Expect(err).To(HaveOccurred())
	})

	It("doesn't decode invalid tokens", func() {
		token, err := tp.NewToken([]byte("foobar"))
		Expect(err).ToNot(HaveOccurred())
		_, err = tp.DecodeToken(token[1:]) // the token is invalid without the first byte
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("message authentication failed"))
	})

	It("errors when decoding too short tokens", func() {
		_, err := tp.DecodeToken([]byte("foobar"))
		Expect(err).To(MatchError("token too short: 6"))
	})
})
