package handshake

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/tls"
	"fmt"

	"github.com/quic-go/quic-go/internal/protocol"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Long Header AEAD", func() {
	for _, ver := range []protocol.VersionNumber{protocol.Version1, protocol.Version2} {
		v := ver

		Context(fmt.Sprintf("using version %s", v), func() {
			for i := range cipherSuites {
				cs := cipherSuites[i]

				Context(fmt.Sprintf("using %s", tls.CipherSuiteName(cs.ID)), func() {
					getSealerAndOpener := func() (LongHeaderSealer, LongHeaderOpener) {
						key := make([]byte, 16)
						hpKey := make([]byte, 16)
						rand.Read(key)
						rand.Read(hpKey)
						block, err := aes.NewCipher(key)
						Expect(err).ToNot(HaveOccurred())
						aead, err := cipher.NewGCM(block)
						Expect(err).ToNot(HaveOccurred())

						return newLongHeaderSealer(aead, newHeaderProtector(cs, hpKey, true, v)),
							newLongHeaderOpener(aead, newHeaderProtector(cs, hpKey, true, v))
					}

					Context("message encryption", func() {
						msg := []byte("Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua.")
						ad := []byte("Donec in velit neque.")

						It("encrypts and decrypts a message", func() {
							sealer, opener := getSealerAndOpener()
							encrypted := sealer.Seal(nil, msg, 0x1337, ad)
							opened, err := opener.Open(nil, encrypted, 0x1337, ad)
							Expect(err).ToNot(HaveOccurred())
							Expect(opened).To(Equal(msg))
						})

						It("fails to open a message if the associated data is not the same", func() {
							sealer, opener := getSealerAndOpener()
							encrypted := sealer.Seal(nil, msg, 0x1337, ad)
							_, err := opener.Open(nil, encrypted, 0x1337, []byte("wrong ad"))
							Expect(err).To(MatchError(ErrDecryptionFailed))
						})

						It("fails to open a message if the packet number is not the same", func() {
							sealer, opener := getSealerAndOpener()
							encrypted := sealer.Seal(nil, msg, 0x1337, ad)
							_, err := opener.Open(nil, encrypted, 0x42, ad)
							Expect(err).To(MatchError(ErrDecryptionFailed))
						})

						It("decodes the packet number", func() {
							sealer, opener := getSealerAndOpener()
							encrypted := sealer.Seal(nil, msg, 0x1337, ad)
							_, err := opener.Open(nil, encrypted, 0x1337, ad)
							Expect(err).ToNot(HaveOccurred())
							Expect(opener.DecodePacketNumber(0x38, protocol.PacketNumberLen1)).To(BeEquivalentTo(0x1338))
						})

						It("ignores packets it can't decrypt for packet number derivation", func() {
							sealer, opener := getSealerAndOpener()
							encrypted := sealer.Seal(nil, msg, 0x1337, ad)
							_, err := opener.Open(nil, encrypted[:len(encrypted)-1], 0x1337, ad)
							Expect(err).To(HaveOccurred())
							Expect(opener.DecodePacketNumber(0x38, protocol.PacketNumberLen1)).To(BeEquivalentTo(0x38))
						})
					})

					Context("header encryption", func() {
						It("encrypts and encrypts the header", func() {
							sealer, opener := getSealerAndOpener()
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

						It("encrypts and encrypts the header, for a 0xfff..fff sample", func() {
							sealer, opener := getSealerAndOpener()
							var lastFourBitsDifferent int
							for i := 0; i < 100; i++ {
								sample := bytes.Repeat([]byte{0xff}, 16)
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
						})

						It("fails to decrypt the header when using a different sample", func() {
							sealer, opener := getSealerAndOpener()
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
			}
		})
	}
})
