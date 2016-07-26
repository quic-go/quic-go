package crypto

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Crypto/NullAEAD", func() {
	It("opens", func() {
		aad := []byte("All human beings are born free and equal in dignity and rights.")
		plainText := []byte("They are endowed with reason and conscience and should act towards one another in a spirit of brotherhood.")
		hash := []byte{0x98, 0x9b, 0x33, 0x3f, 0xe8, 0xde, 0x32, 0x5c, 0xa6, 0x7f, 0x9c, 0xf7}
		cipherText := append(hash, plainText...)
		aead := &NullAEAD{}
		res, err := aead.Open(nil, cipherText, 0, aad)
		Expect(err).ToNot(HaveOccurred())
		Expect(res).To(Equal([]byte("They are endowed with reason and conscience and should act towards one another in a spirit of brotherhood.")))
	})

	It("fails", func() {
		aad := []byte("All human beings are born free and equal in dignity and rights..")
		plainText := []byte("They are endowed with reason and conscience and should act towards one another in a spirit of brotherhood.")
		hash := []byte{0x98, 0x9b, 0x33, 0x3f, 0xe8, 0xde, 0x32, 0x5c, 0xa6, 0x7f, 0x9c, 0xf7}
		cipherText := append(hash, plainText...)
		aead := &NullAEAD{}
		_, err := aead.Open(nil, cipherText, 0, aad)
		Expect(err).To(HaveOccurred())
	})

	It("seals", func() {
		aad := []byte("All human beings are born free and equal in dignity and rights.")
		plainText := []byte("They are endowed with reason and conscience and should act towards one another in a spirit of brotherhood.")
		aead := &NullAEAD{}
		Expect(aead.Seal(nil, plainText, 0, aad)).To(Equal(append([]byte{0x98, 0x9b, 0x33, 0x3f, 0xe8, 0xde, 0x32, 0x5c, 0xa6, 0x7f, 0x9c, 0xf7}, []byte("They are endowed with reason and conscience and should act towards one another in a spirit of brotherhood.")...)))
	})

	It("rejects short ciphertexts", func() {
		_, err := NullAEAD{}.Open(nil, nil, 0, nil)
		Expect(err).To(MatchError("NullAEAD: ciphertext cannot be less than 12 bytes long"))
	})

	It("seals in-place", func() {
		aead := &NullAEAD{}
		buf := make([]byte, 6, 12+6)
		copy(buf, []byte("foobar"))
		res := aead.Seal(buf[0:0], buf, 0, nil)
		buf = buf[:12+6]
		Expect(buf[12:]).To(Equal([]byte("foobar")))
		Expect(res[12:]).To(Equal([]byte("foobar")))
	})
})
