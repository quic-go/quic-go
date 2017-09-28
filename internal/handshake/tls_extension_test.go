package handshake

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("TLS extension body", func() {
	// 	var server, client mint.AppExtensionHandler
	// 	var el mint.ExtensionList

	// 	BeforeEach(func() {
	// 		server = &extensionHandler{perspective: protocol.PerspectiveServer}
	// 		client = &extensionHandler{perspective: protocol.PerspectiveClient}
	// 		// el = make(mint.ExtensionList, 0)
	// 		// TODO: initialize el with some dummy extensions
	// 	})

	// 	It("writes and reads a ClientHello", func() {
	// 		err := client.Send(mint.HandshakeTypeClientHello, &el)
	// 		Expect(err).ToNot(HaveOccurred())
	// 		ch := &tlsExtensionBody{}
	// 		found := el.Find(ch)
	// 		Expect(found).To(BeTrue())
	// 		err = server.Receive(mint.HandshakeTypeClientHello, &el)
	// 		Expect(err).ToNot(HaveOccurred())
	// 	})
	var extBody *tlsExtensionBody

	BeforeEach(func() {
		extBody = &tlsExtensionBody{}
	})

	It("has the right TLS extension type", func() {
		Expect(extBody.Type()).To(BeEquivalentTo(quicTLSExtensionType))
	})

	It("saves the body when unmarshalling", func() {
		n, err := extBody.Unmarshal([]byte("foobar"))
		Expect(err).ToNot(HaveOccurred())
		Expect(n).To(Equal(6))
		Expect(extBody.data).To(Equal([]byte("foobar")))
	})

	It("returns the body when marshalling", func() {
		extBody.data = []byte("foo")
		data, err := extBody.Marshal()
		Expect(err).ToNot(HaveOccurred())
		Expect(data).To(Equal([]byte("foo")))
	})
})
