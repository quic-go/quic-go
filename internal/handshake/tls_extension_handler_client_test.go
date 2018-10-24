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

var _ = Describe("TLS Extension Handler, for the client", func() {
	var (
		handler    *extensionHandlerClient
		paramsChan <-chan TransportParameters
	)
	version := protocol.VersionNumber(0x42)

	BeforeEach(func() {
		var h tlsExtensionHandler
		h, paramsChan = newExtensionHandlerClient(
			&TransportParameters{},
			version,
			nil,
			version,
			utils.DefaultLogger,
		)
		handler = h.(*extensionHandlerClient)
	})

	Context("sending", func() {
		It("only adds TransportParameters for the ClientHello", func() {
			// test 2 other handshake types
			exts := handler.GetExtensions(uint8(typeCertificateRequest))
			Expect(exts).To(BeEmpty())
			exts = handler.GetExtensions(uint8(typeEncryptedExtensions))
			Expect(exts).To(BeEmpty())
		})

		It("adds TransportParameters to the ClientHello", func() {
			handler.initialVersion = 13
			exts := handler.GetExtensions(uint8(typeClientHello))
			Expect(exts).To(HaveLen(1))
			chtp := &clientHelloTransportParameters{}
			Expect(chtp.Unmarshal(exts[0].Data)).To(Succeed())
			Expect(chtp.InitialVersion).To(BeEquivalentTo(13))
		})
	})

	Context("receiving", func() {
		var parameters TransportParameters

		getEncryptedExtensions := func(params TransportParameters) qtls.Extension {
			return qtls.Extension{
				Type: quicTLSExtensionType,
				Data: (&encryptedExtensionsTransportParameters{
					Parameters:        params,
					NegotiatedVersion: version,
					SupportedVersions: []protocol.VersionNumber{handler.version},
				}).Marshal(),
			}
		}

		BeforeEach(func() {
			parameters = TransportParameters{
				IdleTimeout:         0x1337 * time.Second,
				StatelessResetToken: bytes.Repeat([]byte{0}, 16),
			}
		})

		It("sends the transport parameters on the channel", func() {
			done := make(chan struct{})
			go func() {
				defer GinkgoRecover()
				ext := getEncryptedExtensions(parameters)
				err := handler.ReceivedExtensions(uint8(typeEncryptedExtensions), []qtls.Extension{ext})
				Expect(err).ToNot(HaveOccurred())
				close(done)
			}()
			var params TransportParameters
			Consistently(done).ShouldNot(BeClosed())
			Expect(paramsChan).To(Receive(&params))
			Expect(params.IdleTimeout).To(Equal(0x1337 * time.Second))
			Eventually(done).Should(BeClosed())
		})

		It("errors if the EncryptedExtensions message doesn't contain TransportParameters", func() {
			err := handler.ReceivedExtensions(uint8(typeEncryptedExtensions), nil)
			Expect(err).To(MatchError("EncryptedExtensions message didn't contain a QUIC extension"))
		})

		It("ignores messages without TransportParameters, if they are not required", func() {
			Expect(handler.ReceivedExtensions(uint8(typeCertificateVerify), nil)).To(Succeed())
		})

		It("errors when it can't parse the TransportParameters", func() {
			ext := qtls.Extension{
				Type: quicTLSExtensionType,
				Data: []byte("invalid extension data"),
			}
			err := handler.ReceivedExtensions(uint8(typeEncryptedExtensions), []qtls.Extension{ext})
			Expect(err).To(HaveOccurred()) // this will be some kind of decoding error
		})

		It("rejects TransportParameters if they don't contain the stateless reset token", func() {
			parameters.StatelessResetToken = nil
			ext := getEncryptedExtensions(parameters)
			err := handler.ReceivedExtensions(uint8(typeEncryptedExtensions), []qtls.Extension{ext})
			Expect(err).To(MatchError("server didn't sent stateless_reset_token"))
		})

		Context("Version Negotiation", func() {
			It("accepts a valid version negotiation", func() {
				done := make(chan struct{})
				go func() {
					defer GinkgoRecover()
					Eventually(paramsChan).Should(Receive())
					close(done)
				}()

				handler.initialVersion = 13
				handler.version = 37
				handler.supportedVersions = []protocol.VersionNumber{13, 37, 42}
				ext := qtls.Extension{
					Type: quicTLSExtensionType,
					Data: (&encryptedExtensionsTransportParameters{
						Parameters:        parameters,
						NegotiatedVersion: 37,
						SupportedVersions: []protocol.VersionNumber{36, 37, 38},
					}).Marshal(),
				}
				err := handler.ReceivedExtensions(uint8(typeEncryptedExtensions), []qtls.Extension{ext})
				Expect(err).ToNot(HaveOccurred())
				Eventually(done).Should(BeClosed())
			})

			It("errors if the current version doesn't match negotiated_version", func() {
				handler.initialVersion = 13
				handler.version = 37
				handler.supportedVersions = []protocol.VersionNumber{13, 37, 42}
				ext := qtls.Extension{
					Type: quicTLSExtensionType,
					Data: (&encryptedExtensionsTransportParameters{
						Parameters:        parameters,
						NegotiatedVersion: 38,
						SupportedVersions: []protocol.VersionNumber{36, 37, 38},
					}).Marshal(),
				}
				err := handler.ReceivedExtensions(uint8(typeEncryptedExtensions), []qtls.Extension{ext})
				Expect(err).To(MatchError("VersionNegotiationMismatch: current version doesn't match negotiated_version"))
			})

			It("errors if the current version is not contained in the server's supported versions", func() {
				handler.version = 42
				ext := qtls.Extension{
					Type: quicTLSExtensionType,
					Data: (&encryptedExtensionsTransportParameters{
						NegotiatedVersion: 42,
						SupportedVersions: []protocol.VersionNumber{43, 44},
					}).Marshal(),
				}
				err := handler.ReceivedExtensions(uint8(typeEncryptedExtensions), []qtls.Extension{ext})
				Expect(err).To(MatchError("VersionNegotiationMismatch: current version not included in the supported versions"))
			})

			It("errors if version negotiation was performed, but would have picked a different version based on the supported version list", func() {
				handler.version = 42
				handler.initialVersion = 41
				handler.supportedVersions = []protocol.VersionNumber{43, 42, 41}
				serverSupportedVersions := []protocol.VersionNumber{42, 43}
				// check that version negotiation would have led us to pick version 43
				ver, ok := protocol.ChooseSupportedVersion(handler.supportedVersions, serverSupportedVersions)
				Expect(ok).To(BeTrue())
				Expect(ver).To(Equal(protocol.VersionNumber(43)))
				ext := qtls.Extension{
					Type: quicTLSExtensionType,
					Data: (&encryptedExtensionsTransportParameters{
						NegotiatedVersion: 42,
						SupportedVersions: serverSupportedVersions,
					}).Marshal(),
				}
				err := handler.ReceivedExtensions(uint8(typeEncryptedExtensions), []qtls.Extension{ext})
				Expect(err).To(MatchError("VersionNegotiationMismatch: would have picked a different version"))
			})

			It("doesn't error if it would have picked a different version based on the supported version list, if no version negotiation was performed", func() {
				done := make(chan struct{})
				go func() {
					defer GinkgoRecover()
					Eventually(paramsChan).Should(Receive())
					close(done)
				}()

				handler.version = 42
				handler.initialVersion = 42 // version == initialVersion means no version negotiation was performed
				handler.supportedVersions = []protocol.VersionNumber{43, 42, 41}
				serverSupportedVersions := []protocol.VersionNumber{42, 43}
				// check that version negotiation would have led us to pick version 43
				ver, ok := protocol.ChooseSupportedVersion(handler.supportedVersions, serverSupportedVersions)
				Expect(ok).To(BeTrue())
				Expect(ver).To(Equal(protocol.VersionNumber(43)))
				ext := qtls.Extension{
					Type: quicTLSExtensionType,
					Data: (&encryptedExtensionsTransportParameters{
						Parameters:        parameters,
						NegotiatedVersion: 42,
						SupportedVersions: serverSupportedVersions,
					}).Marshal(),
				}
				err := handler.ReceivedExtensions(uint8(typeEncryptedExtensions), []qtls.Extension{ext})
				Expect(err).ToNot(HaveOccurred())
				Eventually(done).Should(BeClosed())
			})
		})
	})
})
