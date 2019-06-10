package handshake

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"

	"github.com/lucas-clemente/quic-go/internal/protocol"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("AEAD", func() {
	getLongHeaderSealerAndOpener := func() (LongHeaderSealer, LongHeaderOpener) {
		key := make([]byte, 16)
		hpKey := make([]byte, 16)
		rand.Read(key)
		rand.Read(hpKey)
		block, err := aes.NewCipher(key)
		Expect(err).ToNot(HaveOccurred())
		aead, err := cipher.NewGCM(block)
		Expect(err).ToNot(HaveOccurred())
		hpBlock, err := aes.NewCipher(hpKey)
		Expect(err).ToNot(HaveOccurred())

		iv := make([]byte, 12)
		rand.Read(iv)
		return newSealer(aead, hpBlock, false), newLongHeaderOpener(aead, hpBlock)
	}

	getShortHeaderSealerAndOpener := func() (ShortHeaderSealer, ShortHeaderOpener) {
		key := make([]byte, 16)
		hpKey := make([]byte, 16)
		rand.Read(key)
		rand.Read(hpKey)
		block, err := aes.NewCipher(key)
		Expect(err).ToNot(HaveOccurred())
		aead, err := cipher.NewGCM(block)
		Expect(err).ToNot(HaveOccurred())
		hpBlock, err := aes.NewCipher(hpKey)
		Expect(err).ToNot(HaveOccurred())

		iv := make([]byte, 12)
		rand.Read(iv)
		return newSealer(aead, hpBlock, true), newShortHeaderOpener(aead, hpBlock)
	}

	Context("message encryption", func() {
		msg := []byte("Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua.")
		ad := []byte("Donec in velit neque.")

		It("encrypts and decrypts a message, for long headers", func() {
			sealer, opener := getLongHeaderSealerAndOpener()
			encrypted := sealer.Seal(nil, msg, 0x1337, ad)
			opened, err := opener.Open(nil, encrypted, 0x1337, ad)
			Expect(err).ToNot(HaveOccurred())
			Expect(opened).To(Equal(msg))
		})

		It("encrypts and decrypts a message, for short headers", func() {
			sealer, opener := getShortHeaderSealerAndOpener()
			encrypted := sealer.Seal(nil, msg, 0x1337, ad)
			opened, err := opener.Open(nil, encrypted, 0x1337, protocol.KeyPhaseZero, ad)
			Expect(err).ToNot(HaveOccurred())
			Expect(opened).To(Equal(msg))
		})

		It("fails to open a message if the associated data is not the same", func() {
			sealer, opener := getLongHeaderSealerAndOpener()
			encrypted := sealer.Seal(nil, msg, 0x1337, ad)
			_, err := opener.Open(nil, encrypted, 0x1337, []byte("wrong ad"))
			Expect(err).To(MatchError("cipher: message authentication failed"))
		})

		It("fails to open a message if the packet number is not the same", func() {
			sealer, opener := getLongHeaderSealerAndOpener()
			encrypted := sealer.Seal(nil, msg, 0x1337, ad)
			_, err := opener.Open(nil, encrypted, 0x42, ad)
			Expect(err).To(MatchError("cipher: message authentication failed"))
		})
	})

	Context("header encryption", func() {
		It("encrypts and encrypts the header, for long headers", func() {
			sealer, opener := getLongHeaderSealerAndOpener()
			var lastFourBitsDifferent int
			for i := 0; i < 100; i++ {
				sample := make([]byte, 16)
				rand.Read(sample)
				header := []byte{0xb5, 1, 2, 3, 4, 5, 6, 7, 8, 0xde, 0xad, 0xbe, 0xef}
				sealer.EncryptHeader(sample, &header[0], header[9:13])
				if header[0]&0xf != 0xb5&0xf {
					lastFourBitsDifferent++
				}
				Expect(header[0] & 0xf0).To(Equal(byte(0xb5 & 0xf0)))
				Expect(header[1:9]).To(Equal([]byte{1, 2, 3, 4, 5, 6, 7, 8}))
				Expect(header[9:13]).ToNot(Equal([]byte{0xde, 0xad, 0xbe, 0xef}))
				opener.DecryptHeader(sample, &header[0], header[9:13])
				Expect(header).To(Equal([]byte{0xb5, 1, 2, 3, 4, 5, 6, 7, 8, 0xde, 0xad, 0xbe, 0xef}))
			}
			Expect(lastFourBitsDifferent).To(BeNumerically(">", 75))
		})

		It("encrypts and encrypts the header, for short headers", func() {
			sealer, opener := getShortHeaderSealerAndOpener()
			var lastFiveBitsDifferent int
			for i := 0; i < 100; i++ {
				sample := make([]byte, 16)
				rand.Read(sample)
				header := []byte{0xb5, 1, 2, 3, 4, 5, 6, 7, 8, 0xde, 0xad, 0xbe, 0xef}
				sealer.EncryptHeader(sample, &header[0], header[9:13])
				if header[0]&0x1f != 0xb5&0x1f {
					lastFiveBitsDifferent++
				}
				Expect(header[0] & 0xe0).To(Equal(byte(0xb5 & 0xe0)))
				Expect(header[1:9]).To(Equal([]byte{1, 2, 3, 4, 5, 6, 7, 8}))
				Expect(header[9:13]).ToNot(Equal([]byte{0xde, 0xad, 0xbe, 0xef}))
				opener.DecryptHeader(sample, &header[0], header[9:13])
				Expect(header).To(Equal([]byte{0xb5, 1, 2, 3, 4, 5, 6, 7, 8, 0xde, 0xad, 0xbe, 0xef}))
			}
			Expect(lastFiveBitsDifferent).To(BeNumerically(">", 75))
		})

		It("fails to decrypt the header when using a different sample", func() {
			sealer, opener := getLongHeaderSealerAndOpener()
			header := []byte{0xb5, 1, 2, 3, 4, 5, 6, 7, 8, 0xde, 0xad, 0xbe, 0xef}
			sample := make([]byte, 16)
			rand.Read(sample)
			sealer.EncryptHeader(sample, &header[0], header[9:13])
			rand.Read(sample) // use a different sample
			opener.DecryptHeader(sample, &header[0], header[9:13])
			Expect(header).ToNot(Equal([]byte{0xb5, 1, 2, 3, 4, 5, 6, 7, 8, 0xde, 0xad, 0xbe, 0xef}))
		})
	})
})
