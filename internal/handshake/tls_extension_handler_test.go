package handshake

import (
	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/marten-seemann/qtls"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("TLS Extension Handler, for the server", func() {
	var (
		handlerServer tlsExtensionHandler
		handlerClient tlsExtensionHandler
	)

	BeforeEach(func() {
		handlerServer = newExtensionHandler(
			[]byte("foobar"),
			protocol.PerspectiveServer,
		)
		handlerClient = newExtensionHandler(
			[]byte("raboof"),
			protocol.PerspectiveClient,
		)
	})

	Context("for the server", func() {
		Context("sending", func() {
			It("only adds TransportParameters for the Encrypted Extensions", func() {
				// test 2 other handshake types
				Expect(handlerServer.GetExtensions(uint8(typeCertificate))).To(BeEmpty())
				Expect(handlerServer.GetExtensions(uint8(typeFinished))).To(BeEmpty())
			})

			It("adds TransportParameters to the EncryptedExtensions message", func() {
				exts := handlerServer.GetExtensions(uint8(typeEncryptedExtensions))
				Expect(exts).To(HaveLen(1))
				Expect(exts[0].Type).To(BeEquivalentTo(quicTLSExtensionType))
				Expect(exts[0].Data).To(Equal([]byte("foobar")))
			})
		})

		Context("receiving", func() {
			var chExts []qtls.Extension

			BeforeEach(func() {
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
				go func() {
					defer GinkgoRecover()
					handlerServer.ReceivedExtensions(uint8(typeFinished), chExts)
				}()

				Consistently(handlerServer.TransportParameters()).ShouldNot(Receive())
			})
		})
	})

	Context("for the client", func() {
		Context("sending", func() {
			It("only adds TransportParameters for the Encrypted Extensions", func() {
				// test 2 other handshake types
				Expect(handlerClient.GetExtensions(uint8(typeCertificate))).To(BeEmpty())
				Expect(handlerClient.GetExtensions(uint8(typeFinished))).To(BeEmpty())
			})

			It("adds TransportParameters to the ClientHello message", func() {
				exts := handlerClient.GetExtensions(uint8(typeClientHello))
				Expect(exts).To(HaveLen(1))
				Expect(exts[0].Type).To(BeEquivalentTo(quicTLSExtensionType))
				Expect(exts[0].Data).To(Equal([]byte("raboof")))
			})
		})

		Context("receiving", func() {
			var chExts []qtls.Extension

			BeforeEach(func() {
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
				go func() {
					defer GinkgoRecover()
					handlerClient.ReceivedExtensions(uint8(typeFinished), chExts)
				}()

				Consistently(handlerClient.TransportParameters()).ShouldNot(Receive())
			})
		})
	})
})
