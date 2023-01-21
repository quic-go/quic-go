package handshake

import (
	"fmt"

	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/qtls"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("TLS Extension Handler, for the server", func() {
	var (
		handlerServer tlsExtensionHandler
		handlerClient tlsExtensionHandler
		version       protocol.VersionNumber
	)

	BeforeEach(func() {
		version = protocol.VersionDraft29
	})

	JustBeforeEach(func() {
		handlerServer = newExtensionHandler(
			[]byte("foobar"),
			protocol.PerspectiveServer,
			version,
		)
		handlerClient = newExtensionHandler(
			[]byte("raboof"),
			protocol.PerspectiveClient,
			version,
		)
	})

	Context("for the server", func() {
		for _, ver := range []protocol.VersionNumber{protocol.VersionDraft29, protocol.Version1} {
			v := ver

			Context(fmt.Sprintf("sending, for version %s", v), func() {
				var extensionType uint16

				BeforeEach(func() {
					version = v
					if v == protocol.VersionDraft29 {
						extensionType = quicTLSExtensionTypeOldDrafts
					} else {
						extensionType = quicTLSExtensionType
					}
				})

				It("only adds TransportParameters for the Encrypted Extensions", func() {
					// test 2 other handshake types
					Expect(handlerServer.GetExtensions(uint8(typeCertificate))).To(BeEmpty())
					Expect(handlerServer.GetExtensions(uint8(typeFinished))).To(BeEmpty())
				})

				It("adds TransportParameters to the EncryptedExtensions message", func() {
					exts := handlerServer.GetExtensions(uint8(typeEncryptedExtensions))
					Expect(exts).To(HaveLen(1))
					Expect(exts[0].Type).To(BeEquivalentTo(extensionType))
					Expect(exts[0].Data).To(Equal([]byte("foobar")))
				})
			})
		}

		Context("receiving", func() {
			var chExts []qtls.Extension

			JustBeforeEach(func() {
				chExts = handlerClient.GetExtensions(uint8(typeClientHello))
				Expect(chExts).To(HaveLen(1))
			})

			It("sends the extension on the channel", func() {
				go func() {
					defer GinkgoRecover()
					handlerServer.ReceivedExtensions(uint8(typeClientHello), chExts)
				}()

				var data []byte
				Eventually(handlerServer.TransportParameters()).Should(Receive(&data))
				Expect(data).To(Equal([]byte("raboof")))
			})

			It("sends nil on the channel if the extension is missing", func() {
				go func() {
					defer GinkgoRecover()
					handlerServer.ReceivedExtensions(uint8(typeClientHello), nil)
				}()

				var data []byte
				Eventually(handlerServer.TransportParameters()).Should(Receive(&data))
				Expect(data).To(BeEmpty())
			})

			It("ignores extensions with different code points", func() {
				go func() {
					defer GinkgoRecover()
					exts := []qtls.Extension{{Type: 0x1337, Data: []byte("invalid")}}
					handlerServer.ReceivedExtensions(uint8(typeClientHello), exts)
				}()

				var data []byte
				Eventually(handlerServer.TransportParameters()).Should(Receive())
				Expect(data).To(BeEmpty())
			})

			It("ignores extensions that are not sent with the ClientHello", func() {
				done := make(chan struct{})
				go func() {
					defer GinkgoRecover()
					handlerServer.ReceivedExtensions(uint8(typeFinished), chExts)
					close(done)
				}()

				Consistently(handlerServer.TransportParameters()).ShouldNot(Receive())
				Eventually(done).Should(BeClosed())
			})
		})
	})

	Context("for the client", func() {
		for _, ver := range []protocol.VersionNumber{protocol.VersionDraft29, protocol.Version1} {
			v := ver

			Context(fmt.Sprintf("sending, for version %s", v), func() {
				var extensionType uint16

				BeforeEach(func() {
					version = v
					if v == protocol.VersionDraft29 {
						extensionType = quicTLSExtensionTypeOldDrafts
					} else {
						extensionType = quicTLSExtensionType
					}
				})

				It("only adds TransportParameters for the Encrypted Extensions", func() {
					// test 2 other handshake types
					Expect(handlerClient.GetExtensions(uint8(typeCertificate))).To(BeEmpty())
					Expect(handlerClient.GetExtensions(uint8(typeFinished))).To(BeEmpty())
				})

				It("adds TransportParameters to the ClientHello message", func() {
					exts := handlerClient.GetExtensions(uint8(typeClientHello))
					Expect(exts).To(HaveLen(1))
					Expect(exts[0].Type).To(BeEquivalentTo(extensionType))
					Expect(exts[0].Data).To(Equal([]byte("raboof")))
				})
			})
		}

		Context("receiving", func() {
			var chExts []qtls.Extension

			JustBeforeEach(func() {
				chExts = handlerServer.GetExtensions(uint8(typeEncryptedExtensions))
				Expect(chExts).To(HaveLen(1))
			})

			It("sends the extension on the channel", func() {
				go func() {
					defer GinkgoRecover()
					handlerClient.ReceivedExtensions(uint8(typeEncryptedExtensions), chExts)
				}()

				var data []byte
				Eventually(handlerClient.TransportParameters()).Should(Receive(&data))
				Expect(data).To(Equal([]byte("foobar")))
			})

			It("sends nil on the channel if the extension is missing", func() {
				go func() {
					defer GinkgoRecover()
					handlerClient.ReceivedExtensions(uint8(typeEncryptedExtensions), nil)
				}()

				var data []byte
				Eventually(handlerClient.TransportParameters()).Should(Receive(&data))
				Expect(data).To(BeEmpty())
			})

			It("ignores extensions with different code points", func() {
				go func() {
					defer GinkgoRecover()
					exts := []qtls.Extension{{Type: 0x1337, Data: []byte("invalid")}}
					handlerClient.ReceivedExtensions(uint8(typeEncryptedExtensions), exts)
				}()

				var data []byte
				Eventually(handlerClient.TransportParameters()).Should(Receive())
				Expect(data).To(BeEmpty())
			})

			It("ignores extensions that are not sent with the EncryptedExtensions", func() {
				done := make(chan struct{})
				go func() {
					defer GinkgoRecover()
					handlerClient.ReceivedExtensions(uint8(typeFinished), chExts)
					close(done)
				}()

				Consistently(handlerClient.TransportParameters()).ShouldNot(Receive())
				Eventually(done).Should(BeClosed())
			})
		})
	})
})
