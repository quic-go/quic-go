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
		res, err := aead.Open(0, aad, cipherText)
		Expect(err).ToNot(HaveOccurred())
		Expect(res).To(Equal([]byte("They are endowed with reason and conscience and should act towards one another in a spirit of brotherhood.")))
	})

	It("fails", func() {
		aad := []byte("All human beings are born free and equal in dignity and rights..")
		plainText := []byte("They are endowed with reason and conscience and should act towards one another in a spirit of brotherhood.")
		hash := []byte{0x98, 0x9b, 0x33, 0x3f, 0xe8, 0xde, 0x32, 0x5c, 0xa6, 0x7f, 0x9c, 0xf7}
		cipherText := append(hash, plainText...)
		aead := &NullAEAD{}
		_, err := aead.Open(0, aad, cipherText)
		Expect(err).To(HaveOccurred())
	})

	It("seals", func() {
		aad := []byte("All human beings are born free and equal in dignity and rights.")
		plainText := []byte("They are endowed with reason and conscience and should act towards one another in a spirit of brotherhood.")
		aead := &NullAEAD{}
		Expect(aead.Seal(0, aad, plainText)).To(Equal(append([]byte{0x98, 0x9b, 0x33, 0x3f, 0xe8, 0xde, 0x32, 0x5c, 0xa6, 0x7f, 0x9c, 0xf7}, []byte("They are endowed with reason and conscience and should act towards one another in a spirit of brotherhood.")...)))
	})

	It("rejects short ciphertexts", func() {
		_, err := NullAEAD{}.Open(0, nil, nil)
		Expect(err).To(MatchError("NullAEAD: ciphertext cannot be less than 12 bytes long"))
	})
})
