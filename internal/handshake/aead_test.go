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
	for _, ver := range []protocol.VersionNumber{protocol.VersionDraft29, protocol.Version1, protocol.Version2} {
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

		Describe("Long Header AEAD", func() {
			var (
				dropped chan struct{} // use a chan because closing it twice will panic
				aead    cipher.AEAD
				hp      headerProtector
			)
			dropCb := func() { close(dropped) }
			msg := []byte("Lorem ipsum dolor sit amet.")
			ad := []byte("Donec in velit neque.")

			BeforeEach(func() {
				dropped = make(chan struct{})
				key := make([]byte, 16)
				hpKey := make([]byte, 16)
				rand.Read(key)
				rand.Read(hpKey)
				block, err := aes.NewCipher(key)
				Expect(err).ToNot(HaveOccurred())
				aead, err = cipher.NewGCM(block)
				Expect(err).ToNot(HaveOccurred())
				hp = newHeaderProtector(cipherSuites[0], hpKey, true, protocol.Version1)
			})

			Context("for the server", func() {
				It("drops keys when first successfully processing a Handshake packet", func() {
					serverOpener := newHandshakeOpener(aead, hp, dropCb, protocol.PerspectiveServer)
					// first try to open an invalid message
					_, err := serverOpener.Open(nil, []byte("invalid"), 0, []byte("invalid"))
					Expect(err).To(HaveOccurred())
					Expect(dropped).ToNot(BeClosed())
					// then open a valid message
					enc := newLongHeaderSealer(aead, hp).Seal(nil, msg, 10, ad)
					_, err = serverOpener.Open(nil, enc, 10, ad)
					Expect(err).ToNot(HaveOccurred())
					Expect(dropped).To(BeClosed())
					// now open the same message again to make sure the callback is only called once
					_, err = serverOpener.Open(nil, enc, 10, ad)
					Expect(err).ToNot(HaveOccurred())
				})

				It("doesn't drop keys when sealing a Handshake packet", func() {
					serverSealer := newHandshakeSealer(aead, hp, dropCb, protocol.PerspectiveServer)
					serverSealer.Seal(nil, msg, 1, ad)
					Expect(dropped).ToNot(BeClosed())
				})
			})

			Context("for the client", func() {
				It("drops keys when first sealing a Handshake packet", func() {
					clientSealer := newHandshakeSealer(aead, hp, dropCb, protocol.PerspectiveClient)
					// seal the first message
					clientSealer.Seal(nil, msg, 1, ad)
					Expect(dropped).To(BeClosed())
					// seal another message to make sure the callback is only called once
					clientSealer.Seal(nil, msg, 2, ad)
				})

				It("doesn't drop keys when processing a Handshake packet", func() {
					enc := newLongHeaderSealer(aead, hp).Seal(nil, msg, 42, ad)
					clientOpener := newHandshakeOpener(aead, hp, dropCb, protocol.PerspectiveClient)
					_, err := clientOpener.Open(nil, enc, 42, ad)
					Expect(err).ToNot(HaveOccurred())
					Expect(dropped).ToNot(BeClosed())
				})
			})
		})
	}
})
