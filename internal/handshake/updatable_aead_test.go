package handshake

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"

	"github.com/lucas-clemente/quic-go/internal/protocol"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

type mockCipherSuite struct{}

var _ cipherSuite = &mockCipherSuite{}

func (c *mockCipherSuite) Hash() crypto.Hash { return crypto.SHA256 }
func (c *mockCipherSuite) KeyLen() int       { return 16 }
func (c *mockCipherSuite) IVLen() int        { return 12 }
func (c *mockCipherSuite) AEAD(key, _ []byte) cipher.AEAD {
	block, err := aes.NewCipher(key)
	Expect(err).ToNot(HaveOccurred())
	gcm, err := cipher.NewGCM(block)
	Expect(err).ToNot(HaveOccurred())
	return gcm
}

var _ = Describe("Updatable AEAD", func() {
	getAEAD := func() *updatableAEAD {
		trafficSecret := make([]byte, 16)
		rand.Read(trafficSecret)

		u := newUpdatableAEAD()
		u.SetReadKey(&mockCipherSuite{}, trafficSecret)
		u.SetWriteKey(&mockCipherSuite{}, trafficSecret)
		return u
	}

	Context("message encryption", func() {
		msg := []byte("Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua.")
		ad := []byte("Donec in velit neque.")

		It("encrypts and decrypts a message", func() {
			aead := getAEAD()
			encrypted := aead.Seal(nil, msg, 0x1337, ad)
			opened, err := aead.Open(nil, encrypted, 0x1337, protocol.KeyPhaseZero, ad)
			Expect(err).ToNot(HaveOccurred())
			Expect(opened).To(Equal(msg))
		})

		It("fails to open a message if the associated data is not the same", func() {
			aead := getAEAD()
			encrypted := aead.Seal(nil, msg, 0x1337, ad)
			_, err := aead.Open(nil, encrypted, 0x1337, protocol.KeyPhaseZero, []byte("wrong ad"))
			Expect(err).To(MatchError("cipher: message authentication failed"))
		})

		It("fails to open a message if the packet number is not the same", func() {
			aead := getAEAD()
			encrypted := aead.Seal(nil, msg, 0x1337, ad)
			_, err := aead.Open(nil, encrypted, 0x42, protocol.KeyPhaseZero, ad)
			Expect(err).To(MatchError("cipher: message authentication failed"))
		})
	})

	Context("header encryption", func() {
		It("encrypts and decrypts the header", func() {
			aead := getAEAD()
			var lastFiveBitsDifferent int
			for i := 0; i < 100; i++ {
				sample := make([]byte, 16)
				rand.Read(sample)
				header := []byte{0xb5, 1, 2, 3, 4, 5, 6, 7, 8, 0xde, 0xad, 0xbe, 0xef}
				aead.EncryptHeader(sample, &header[0], header[9:13])
				if header[0]&0x1f != 0xb5&0x1f {
					lastFiveBitsDifferent++
				}
				Expect(header[0] & 0xe0).To(Equal(byte(0xb5 & 0xe0)))
				Expect(header[1:9]).To(Equal([]byte{1, 2, 3, 4, 5, 6, 7, 8}))
				Expect(header[9:13]).ToNot(Equal([]byte{0xde, 0xad, 0xbe, 0xef}))
				aead.DecryptHeader(sample, &header[0], header[9:13])
				Expect(header).To(Equal([]byte{0xb5, 1, 2, 3, 4, 5, 6, 7, 8, 0xde, 0xad, 0xbe, 0xef}))
			}
			Expect(lastFiveBitsDifferent).To(BeNumerically(">", 75))
		})
	})
})
