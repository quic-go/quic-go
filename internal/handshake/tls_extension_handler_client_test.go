package handshake

import (
	"bytes"
	"fmt"

	"github.com/bifurcation/mint"
	"github.com/bifurcation/mint/syntax"
	"github.com/lucas-clemente/quic-go/internal/protocol"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("TLS Extension Handler, for the client", func() {
	var (
		handler *extensionHandlerClient
		el      mint.ExtensionList
	)

	BeforeEach(func() {
		handler = NewExtensionHandlerClient(&TransportParameters{}, protocol.VersionWhatever, nil, protocol.VersionWhatever).(*extensionHandlerClient)
		el = make(mint.ExtensionList, 0)
	})

	Context("sending", func() {
		It("only adds TransportParameters for the ClientHello", func() {
			// test 2 other handshake types
			err := handler.Send(mint.HandshakeTypeCertificateRequest, &el)
			Expect(err).ToNot(HaveOccurred())
			Expect(el).To(BeEmpty())
			err = handler.Send(mint.HandshakeTypeEndOfEarlyData, &el)
			Expect(err).ToNot(HaveOccurred())
			Expect(el).To(BeEmpty())
		})

		It("adds TransportParameters to the ClientHello", func() {
			handler.initialVersion = 13
			err := handler.Send(mint.HandshakeTypeClientHello, &el)
			Expect(err).ToNot(HaveOccurred())
			Expect(el).To(HaveLen(1))
			ext := &tlsExtensionBody{}
			found, err := el.Find(ext)
			Expect(err).ToNot(HaveOccurred())
			Expect(found).To(BeTrue())
			chtp := &clientHelloTransportParameters{}
			_, err = syntax.Unmarshal(ext.data, chtp)
			Expect(err).ToNot(HaveOccurred())
			Expect(chtp.InitialVersion).To(BeEquivalentTo(13))
		})
	})

	Context("receiving", func() {
		var fakeBody *tlsExtensionBody
		var parameters map[transportParameterID][]byte

		addEncryptedExtensionsWithParameters := func(paramMap map[transportParameterID][]byte) {
			body, err := syntax.Marshal(encryptedExtensionsTransportParameters{
				Parameters:        parameterMapToList(paramMap),
				SupportedVersions: []uint32{uint32(handler.version)},
			})
			Expect(err).ToNot(HaveOccurred())
			err = el.Add(&tlsExtensionBody{data: body})
			Expect(err).ToNot(HaveOccurred())
		}

		BeforeEach(func() {
			fakeBody = &tlsExtensionBody{data: []byte("foobar foobar")}
			parameters = map[transportParameterID][]byte{
				initialMaxStreamDataParameterID:   []byte{0x11, 0x22, 0x33, 0x44},
				initialMaxDataParameterID:         []byte{0x22, 0x33, 0x44, 0x55},
				initialMaxStreamIDBiDiParameterID: []byte{0x33, 0x44, 0x55, 0x66},
				idleTimeoutParameterID:            []byte{0x13, 0x37},
				statelessResetTokenParameterID:    bytes.Repeat([]byte{0}, 16),
			}
		})

		It("accepts the TransportParameters on the EncryptedExtensions message", func() {
			addEncryptedExtensionsWithParameters(parameters)
			err := handler.Receive(mint.HandshakeTypeEncryptedExtensions, &el)
			Expect(err).ToNot(HaveOccurred())
			var params TransportParameters
			Expect(handler.GetPeerParams()).To(Receive(&params))
			Expect(params.StreamFlowControlWindow).To(BeEquivalentTo(0x11223344))
		})

		It("errors if the EncryptedExtensions message doesn't contain TransportParameters", func() {
			err := handler.Receive(mint.HandshakeTypeEncryptedExtensions, &el)
			Expect(err).To(MatchError("EncryptedExtensions message didn't contain a QUIC extension"))
		})

		It("rejects the TransportParameters on a wrong handshake types", func() {
			err := el.Add(fakeBody)
			Expect(err).ToNot(HaveOccurred())
			err = handler.Receive(mint.HandshakeTypeCertificate, &el)
			Expect(err).To(MatchError(fmt.Sprintf("Unexpected QUIC extension in handshake message %d", mint.HandshakeTypeCertificate)))
		})

		It("ignores messages without TransportParameters, if they are not required", func() {
			err := handler.Receive(mint.HandshakeTypeCertificate, &el)
			Expect(err).ToNot(HaveOccurred())
		})

		// TODO: fix this when implementing the NewSessionTicket
		It("ignors the TransportParameters in the NewSessionTicket message", func() {
			err := el.Add(fakeBody)
			Expect(err).ToNot(HaveOccurred())
			err = handler.Receive(mint.HandshakeTypeNewSessionTicket, &el)
			Expect(err).ToNot(HaveOccurred())
		})

		It("errors when it can't parse the TransportParameters", func() {
			err := el.Add(fakeBody)
			Expect(err).ToNot(HaveOccurred())
			err = handler.Receive(mint.HandshakeTypeEncryptedExtensions, &el)
			Expect(err).To(HaveOccurred()) // this will be some kind of decoding error
		})

		It("rejects TransportParameters if they don't contain the stateless reset token", func() {
			delete(parameters, statelessResetTokenParameterID)
			addEncryptedExtensionsWithParameters(parameters)
			err := handler.Receive(mint.HandshakeTypeEncryptedExtensions, &el)
			Expect(err).To(MatchError("server didn't sent stateless_reset_token"))
		})

		It("errors if the stateless reset token has the wrong length", func() {
			parameters[statelessResetTokenParameterID] = bytes.Repeat([]byte{0}, 15) // should be 16
			addEncryptedExtensionsWithParameters(parameters)
			err := handler.Receive(mint.HandshakeTypeEncryptedExtensions, &el)
			Expect(err).To(MatchError("wrong length for stateless_reset_token: 15 (expected 16)"))
		})

		Context("Version Negotiation", func() {
			It("accepts a valid version negotiation", func() {
				handler.initialVersion = 13
				handler.version = 37
				handler.supportedVersions = []protocol.VersionNumber{13, 37, 42}
				body, err := syntax.Marshal(encryptedExtensionsTransportParameters{
					Parameters:        parameterMapToList(parameters),
					NegotiatedVersion: 37,
					SupportedVersions: []uint32{36, 37, 38},
				})
				Expect(err).ToNot(HaveOccurred())
				err = el.Add(&tlsExtensionBody{data: body})
				Expect(err).ToNot(HaveOccurred())
				err = handler.Receive(mint.HandshakeTypeEncryptedExtensions, &el)
				Expect(err).ToNot(HaveOccurred())
			})

			It("errors if the current version doesn't match negotiated_version", func() {
				handler.initialVersion = 13
				handler.version = 37
				handler.supportedVersions = []protocol.VersionNumber{13, 37, 42}
				body, err := syntax.Marshal(encryptedExtensionsTransportParameters{
					Parameters:        parameterMapToList(parameters),
					NegotiatedVersion: 38,
					SupportedVersions: []uint32{36, 37, 38},
				})
				Expect(err).ToNot(HaveOccurred())
				err = el.Add(&tlsExtensionBody{data: body})
				Expect(err).ToNot(HaveOccurred())
				err = handler.Receive(mint.HandshakeTypeEncryptedExtensions, &el)
				Expect(err).To(MatchError("VersionNegotiationMismatch: current version doesn't match negotiated_version"))
			})

			It("errors if the current version is not contained in the server's supported versions", func() {
				handler.version = 42
				body, err := syntax.Marshal(encryptedExtensionsTransportParameters{
					NegotiatedVersion: 42,
					SupportedVersions: []uint32{43, 44},
				})
				Expect(err).ToNot(HaveOccurred())
				err = el.Add(&tlsExtensionBody{data: body})
				Expect(err).ToNot(HaveOccurred())
				err = handler.Receive(mint.HandshakeTypeEncryptedExtensions, &el)
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
				ssv := make([]uint32, len(serverSupportedVersions))
				for i, v := range serverSupportedVersions {
					ssv[i] = uint32(v)
				}
				body, err := syntax.Marshal(encryptedExtensionsTransportParameters{
					NegotiatedVersion: 42,
					SupportedVersions: ssv,
				})
				Expect(err).ToNot(HaveOccurred())
				err = el.Add(&tlsExtensionBody{data: body})
				Expect(err).ToNot(HaveOccurred())
				err = handler.Receive(mint.HandshakeTypeEncryptedExtensions, &el)
				Expect(err).To(MatchError("VersionNegotiationMismatch: would have picked a different version"))
			})

			It("doesn't error if it would have picked a different version based on the supported version list, if no version negotiation was performed", func() {
				handler.version = 42
				handler.initialVersion = 42 // version == initialVersion means no version negotiation was performed
				handler.supportedVersions = []protocol.VersionNumber{43, 42, 41}
				serverSupportedVersions := []protocol.VersionNumber{42, 43}
				// check that version negotiation would have led us to pick version 43
				ver, ok := protocol.ChooseSupportedVersion(handler.supportedVersions, serverSupportedVersions)
				Expect(ok).To(BeTrue())
				Expect(ver).To(Equal(protocol.VersionNumber(43)))
				ssv := make([]uint32, len(serverSupportedVersions))
				for i, v := range serverSupportedVersions {
					ssv[i] = uint32(v)
				}
				body, err := syntax.Marshal(encryptedExtensionsTransportParameters{
					Parameters:        parameterMapToList(parameters),
					NegotiatedVersion: 42,
					SupportedVersions: ssv,
				})
				Expect(err).ToNot(HaveOccurred())
				err = el.Add(&tlsExtensionBody{data: body})
				Expect(err).ToNot(HaveOccurred())
				err = handler.Receive(mint.HandshakeTypeEncryptedExtensions, &el)
				Expect(err).ToNot(HaveOccurred())
			})
		})
	})
})
