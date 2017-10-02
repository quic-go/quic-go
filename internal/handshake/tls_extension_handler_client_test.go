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
	var handler *extensionHandlerClient
	var el mint.ExtensionList

	BeforeEach(func() {
		pn := &paramsNegotiator{}
		handler = newExtensionHandlerClient(pn, protocol.VersionWhatever, protocol.VersionWhatever)
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
			handler.version = 37
			err := handler.Send(mint.HandshakeTypeClientHello, &el)
			Expect(err).ToNot(HaveOccurred())
			Expect(el).To(HaveLen(1))
			ext := &tlsExtensionBody{}
			found := el.Find(ext)
			Expect(found).To(BeTrue())
			chtp := &clientHelloTransportParameters{}
			_, err = syntax.Unmarshal(ext.data, chtp)
			Expect(err).ToNot(HaveOccurred())
			Expect(chtp.InitialVersion).To(BeEquivalentTo(13))
			Expect(chtp.NegotiatedVersion).To(BeEquivalentTo(37))
		})
	})

	Context("receiving", func() {
		var fakeBody *tlsExtensionBody
		var parameters map[transportParameterID][]byte

		paramaterMapToExtensionBody := func(paramMap map[transportParameterID][]byte) *tlsExtensionBody {
			var params []transportParameter
			for id, val := range paramMap {
				params = append(params, transportParameter{id, val})
			}
			body, err := syntax.Marshal(encryptedExtensionsTransportParameters{Parameters: params})
			Expect(err).ToNot(HaveOccurred())
			return &tlsExtensionBody{data: body}
		}

		BeforeEach(func() {
			fakeBody = &tlsExtensionBody{data: []byte("foobar foobar")}
			parameters = map[transportParameterID][]byte{
				initialMaxStreamDataParameterID: []byte{0x11, 0x22, 0x33, 0x44},
				initialMaxDataParameterID:       []byte{0x22, 0x33, 0x44, 0x55},
				initialMaxStreamIDParameterID:   []byte{0x33, 0x44, 0x55, 0x66},
				idleTimeoutParameterID:          []byte{0x13, 0x37},
				statelessResetTokenParameterID:  bytes.Repeat([]byte{0}, 16),
			}
		})

		It("accepts the TransportParameters on the EncryptedExtensions message", func() {
			err := el.Add(paramaterMapToExtensionBody(parameters))
			Expect(err).ToNot(HaveOccurred())
			err = handler.Receive(mint.HandshakeTypeEncryptedExtensions, &el)
			Expect(err).ToNot(HaveOccurred())
			Expect(handler.params.GetSendStreamFlowControlWindow()).To(BeEquivalentTo(0x11223344))
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
			err := el.Add(paramaterMapToExtensionBody(parameters))
			Expect(err).ToNot(HaveOccurred())
			err = handler.Receive(mint.HandshakeTypeEncryptedExtensions, &el)
			Expect(err).To(MatchError("server didn't sent stateless_reset_token"))
		})

		It("errors if the stateless reset token has the wrong length", func() {
			parameters[statelessResetTokenParameterID] = bytes.Repeat([]byte{0}, 15) // should be 16
			err := el.Add(paramaterMapToExtensionBody(parameters))
			Expect(err).ToNot(HaveOccurred())
			err = handler.Receive(mint.HandshakeTypeEncryptedExtensions, &el)
			Expect(err).To(MatchError("wrong length for stateless_reset_token: 15 (expected 16)"))
		})
	})
})
