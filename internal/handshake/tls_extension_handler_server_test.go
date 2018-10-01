package handshake

import (
	"bytes"
	"time"

	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/utils"
	"github.com/marten-seemann/qtls"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("TLS Extension Handler, for the server", func() {
	var (
		handler    *extensionHandlerServer
		paramsChan <-chan TransportParameters
	)

	BeforeEach(func() {
		var h tlsExtensionHandler
		h, paramsChan = newExtensionHandlerServer(
			&TransportParameters{},
			nil,
			protocol.VersionWhatever,
			utils.DefaultLogger,
		)
		handler = h.(*extensionHandlerServer)
	})

	Context("sending", func() {
		It("only adds TransportParameters for the Encrypted Extensions", func() {
			// test 2 other handshake types
			exts := handler.GetExtensions(uint8(typeCertificate))
			Expect(exts).To(BeEmpty())
			exts = handler.GetExtensions(uint8(typeFinished))
			Expect(exts).To(BeEmpty())
		})

		It("adds TransportParameters to the EncryptedExtensions message", func() {
			handler.version = 666
			versions := []protocol.VersionNumber{13, 37, 42}
			handler.supportedVersions = versions
			exts := handler.GetExtensions(uint8(typeEncryptedExtensions))
			Expect(exts).To(HaveLen(1))
			eetp := &encryptedExtensionsTransportParameters{}
			Expect(eetp.Unmarshal(exts[0].Data)).To(Succeed())
			Expect(eetp.NegotiatedVersion).To(BeEquivalentTo(666))
			// the SupportedVersions will contain one reserved version number
			Expect(eetp.SupportedVersions).To(HaveLen(len(versions) + 1))
			for _, version := range versions {
				Expect(eetp.SupportedVersions).To(ContainElement(version))
			}
		})
	})

	Context("receiving", func() {
		var parameters TransportParameters

		getClientHello := func(params TransportParameters) qtls.Extension {
			return qtls.Extension{
				Type: quicTLSExtensionType,
				Data: (&clientHelloTransportParameters{Parameters: params}).Marshal(),
			}
		}

		BeforeEach(func() {
			parameters = TransportParameters{IdleTimeout: 0x1337 * time.Second}
		})

		It("sends the transport parameters on the channel", func() {
			done := make(chan struct{})
			go func() {
				defer GinkgoRecover()
				ext := getClientHello(parameters)
				err := handler.ReceivedExtensions(uint8(typeClientHello), []qtls.Extension{ext})
				Expect(err).ToNot(HaveOccurred())
				close(done)
			}()
			var params TransportParameters
			Consistently(done).ShouldNot(BeClosed())
			Expect(paramsChan).To(Receive(&params))
			Expect(params.IdleTimeout).To(Equal(0x1337 * time.Second))
			Eventually(done).Should(BeClosed())
		})

		It("errors if the ClientHello doesn't contain TransportParameters", func() {
			err := handler.ReceivedExtensions(uint8(typeClientHello), nil)
			Expect(err).To(MatchError("ClientHello didn't contain a QUIC extension"))
		})

		It("errors if it can't unmarshal the TransportParameters", func() {
			ext := qtls.Extension{
				Type: quicTLSExtensionType,
				Data: []byte("invalid extension data"),
			}
			err := handler.ReceivedExtensions(uint8(typeClientHello), []qtls.Extension{ext})
			Expect(err).To(HaveOccurred()) // this will be some kind of decoding error
		})

		It("rejects messages that contain a stateless reset token", func() {
			parameters.StatelessResetToken = bytes.Repeat([]byte{0}, 16)
			ext := getClientHello(parameters)
			err := handler.ReceivedExtensions(uint8(typeClientHello), []qtls.Extension{ext})
			Expect(err).To(MatchError("client sent a stateless reset token"))
		})

		Context("Version Negotiation", func() {
			It("accepts a ClientHello, when no version negotiation was performed", func() {
				done := make(chan struct{})
				go func() {
					defer GinkgoRecover()
					<-paramsChan
					close(done)
				}()
				handler.version = 42
				ext := qtls.Extension{
					Type: quicTLSExtensionType,
					Data: (&clientHelloTransportParameters{
						InitialVersion: 42,
						Parameters:     parameters,
					}).Marshal(),
				}
				err := handler.ReceivedExtensions(uint8(typeClientHello), []qtls.Extension{ext})
				Expect(err).ToNot(HaveOccurred())
				Eventually(done).Should(BeClosed())
			})

			It("accepts a valid version negotiation", func() {
				done := make(chan struct{})
				go func() {
					defer GinkgoRecover()
					<-paramsChan
					close(done)
				}()
				handler.version = 42
				handler.supportedVersions = []protocol.VersionNumber{13, 37, 42}
				ext := qtls.Extension{
					Type: quicTLSExtensionType,
					Data: (&clientHelloTransportParameters{
						InitialVersion: 22, // this must be an unsupported version
						Parameters:     parameters,
					}).Marshal(),
				}
				err := handler.ReceivedExtensions(uint8(typeClientHello), []qtls.Extension{ext})
				Expect(err).ToNot(HaveOccurred())
				Eventually(done).Should(BeClosed())
			})

			It("erros when a version negotiation was performed, although we already support the initial version", func() {
				handler.supportedVersions = []protocol.VersionNumber{11, 12, 13}
				handler.version = 13
				ext := qtls.Extension{
					Type: quicTLSExtensionType,
					Data: (&clientHelloTransportParameters{
						InitialVersion: 11, // this is an supported version
					}).Marshal(),
				}
				err := handler.ReceivedExtensions(uint8(typeClientHello), []qtls.Extension{ext})
				Expect(err).To(MatchError("VersionNegotiationMismatch: Client should have used the initial version"))
			})
		})
	})
})
