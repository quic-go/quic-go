package handshake

import (
	"crypto/rand"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

type zeroReader struct{}

func (r *zeroReader) Read(b []byte) (int, error) {
	for i := range b {
		b[i] = 0
	}
	return len(b), nil
}

var _ = Describe("Token Protector", func() {
	var tp tokenProtector

	BeforeEach(func() {
		var err error
		tp, err = newTokenProtector(rand.Reader)
		Expect(err).ToNot(HaveOccurred())
	})

	It("uses the random source", func() {
		tp1, err := newTokenProtector(&zeroReader{})
		Expect(err).ToNot(HaveOccurred())
		tp2, err := newTokenProtector(&zeroReader{})
		Expect(err).ToNot(HaveOccurred())
		t1, err := tp1.NewToken([]byte("foo"))
		Expect(err).ToNot(HaveOccurred())
		t2, err := tp2.NewToken([]byte("foo"))
		Expect(err).ToNot(HaveOccurred())
		Expect(t1).To(Equal(t2))
		tp3, err := newTokenProtector(rand.Reader)
		Expect(err).ToNot(HaveOccurred())
		t3, err := tp3.NewToken([]byte("foo"))
		Expect(err).ToNot(HaveOccurred())
		Expect(t3).ToNot(Equal(t1))
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
