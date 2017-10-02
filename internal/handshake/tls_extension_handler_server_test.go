package handshake

import (
	"fmt"

	"github.com/bifurcation/mint"
	"github.com/bifurcation/mint/syntax"
	"github.com/lucas-clemente/quic-go/internal/protocol"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("TLS Extension Handler, for the server", func() {
	var handler *extensionHandlerServer
	var el mint.ExtensionList

	BeforeEach(func() {
		pn := &paramsNegotiator{}
		handler = newExtensionHandlerServer(pn, nil)
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

		It("adds TransportParameters to the EncryptedExtensions message", func() {
			handler.supportedVersions = []protocol.VersionNumber{13, 37, 42}
			err := handler.Send(mint.HandshakeTypeEncryptedExtensions, &el)
			Expect(err).ToNot(HaveOccurred())
			Expect(el).To(HaveLen(1))
			ext := &tlsExtensionBody{}
			found := el.Find(ext)
			Expect(found).To(BeTrue())
			eetp := &encryptedExtensionsTransportParameters{}
			_, err = syntax.Unmarshal(ext.data, eetp)
			Expect(err).ToNot(HaveOccurred())
			Expect(eetp.SupportedVersions).To(Equal([]uint32{13, 37, 42}))
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
			body, err := syntax.Marshal(clientHelloTransportParameters{Parameters: params})
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
			}
		})

		It("accepts the TransportParameters on the EncryptedExtensions message", func() {
			err := el.Add(paramaterMapToExtensionBody(parameters))
			Expect(err).ToNot(HaveOccurred())
			err = handler.Receive(mint.HandshakeTypeClientHello, &el)
			Expect(err).ToNot(HaveOccurred())
			Expect(handler.params.GetSendStreamFlowControlWindow()).To(BeEquivalentTo(0x11223344))
		})

		It("errors if the ClientHello doesn't contain TransportParameters", func() {
			err := handler.Receive(mint.HandshakeTypeClientHello, &el)
			Expect(err).To(MatchError("ClientHello didn't contain a QUIC extension"))
		})

		It("ignores messages without TransportParameters, if they are not required", func() {
			err := handler.Receive(mint.HandshakeTypeCertificate, &el)
			Expect(err).ToNot(HaveOccurred())
		})

		It("errors if it can't unmarshal the TransportParameters", func() {
			err := el.Add(fakeBody)
			Expect(err).ToNot(HaveOccurred())
			err = handler.Receive(mint.HandshakeTypeClientHello, &el)
			Expect(err).To(HaveOccurred()) // this will be some kind of decoding error
		})

		It("rejects messages other than the ClientHello that contain TransportParameters", func() {
			err := el.Add(paramaterMapToExtensionBody(parameters))
			Expect(err).ToNot(HaveOccurred())
			err = handler.Receive(mint.HandshakeTypeCertificateRequest, &el)
			Expect(err).To(MatchError(fmt.Sprintf("Unexpected QUIC extension in handshake message %d", mint.HandshakeTypeCertificateRequest)))
		})

		It("rejects messages that contain a stateless reset token", func() {
			parameters[statelessResetTokenParameterID] = []byte("reset")
			err := el.Add(paramaterMapToExtensionBody(parameters))
			Expect(err).ToNot(HaveOccurred())
			err = handler.Receive(mint.HandshakeTypeClientHello, &el)
			Expect(err).To(MatchError("client sent a stateless reset token"))
		})
	})
})
