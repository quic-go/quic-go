package handshake

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("AEAD", func() {
	var sealer Sealer
	var opener Opener

	msg := []byte("Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua.")
	ad := []byte("Donec in velit neque.")

	BeforeEach(func() {
		key := make([]byte, 16)
		rand.Read(key)
		block, err := aes.NewCipher(key)
		Expect(err).ToNot(HaveOccurred())
		aead, err := cipher.NewGCM(block)
		Expect(err).ToNot(HaveOccurred())

		iv := make([]byte, 12)
		rand.Read(iv)
		sealer = newSealer(aead, iv)
		opener = newOpener(aead, iv)
	})

	It("encrypts and decrypts a message", func() {
		encrypted := sealer.Seal(nil, msg, 0x1337, ad)
		opened, err := opener.Open(nil, encrypted, 0x1337, ad)
		Expect(err).ToNot(HaveOccurred())
		Expect(opened).To(Equal(msg))
	})

	It("fails to open a message if the associated data is not the same", func() {
		encrypted := sealer.Seal(nil, msg, 0x1337, ad)
		_, err := opener.Open(nil, encrypted, 0x1337, []byte("wrong ad"))
		Expect(err).To(MatchError("cipher: message authentication failed"))
	})

	It("fails to open a message if the packet number is not the same", func() {
		encrypted := sealer.Seal(nil, msg, 0x1337, ad)
		_, err := opener.Open(nil, encrypted, 0x42, ad)
		Expect(err).To(MatchError("cipher: message authentication failed"))
	})
})
