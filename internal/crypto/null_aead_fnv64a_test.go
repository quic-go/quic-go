package crypto

import (
	"encoding/binary"
	"hash/fnv"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("NullAEAD using FNV128a", func() {
	var hash64 []byte
	var aead AEAD
	aad := []byte("All human beings are born free and equal in dignity and rights.")
	plainText := []byte("They are endowed with reason and conscience and should act towards one another in a spirit of brotherhood.")

	BeforeEach(func() {
		aead = &nullAEADFNV64a{}
		hash := fnv.New64a()
		hash.Write(aad)
		hash.Write(plainText)
		hash64 = make([]byte, 8)
		binary.BigEndian.PutUint64(hash64, hash.Sum64())
	})

	It("opens", func() {
		data, err := aead.Open(nil, append(plainText, hash64...), 0, aad)
		Expect(err).ToNot(HaveOccurred())
		Expect(data).To(Equal(plainText))
	})

	It("fails", func() {
		_, err := aead.Open(nil, append(plainText, hash64...), 0, append(aad, []byte{0x42}...))
		Expect(err).To(MatchError("NullAEAD: failed to authenticate received data"))
	})

	It("rejects short ciphertexts", func() {
		_, err := aead.Open(nil, []byte{1, 2, 3, 4, 5, 6, 7}, 0, []byte{})
		Expect(err).To(MatchError("NullAEAD: ciphertext cannot be less than 8 bytes long"))
	})

	It("opens empty messages", func() {
		hash := fnv.New64a()
		h := make([]byte, 8)
		binary.BigEndian.PutUint64(h, hash.Sum64())
		data, err := aead.Open(nil, h, 0, []byte{})
		Expect(err).ToNot(HaveOccurred())
		Expect(data).To(BeEmpty())
	})

	It("seals", func() {
		sealed := aead.Seal(nil, plainText, 0, aad)
		Expect(sealed).To(Equal(append(plainText, hash64...)))
		Expect(sealed).To(HaveLen(len(plainText) + aead.Overhead()))
	})

	It("seals in-place", func() {
		buf := make([]byte, 6, 6+8)
		copy(buf, []byte("foobar"))
		res := aead.Seal(buf[0:0], buf, 0, nil)
		// buf = buf[:8+6]
		Expect(buf[:6]).To(Equal([]byte("foobar")))
		// Expect(res[:6]).To(Equal([]byte("foobar")))
		Expect(buf[0 : 6+8]).To(Equal(res))
	})
})
