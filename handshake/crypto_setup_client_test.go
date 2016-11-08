package handshake

import (
	"github.com/lucas-clemente/quic-go/protocol"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Crypto setup", func() {
	var cs cryptoSetupClient

	BeforeEach(func() {
		cs = cryptoSetupClient{
			cryptoStream: &mockStream{},
		}
	})

	Context("Inchoate CHLO", func() {
		It("has the right values", func() {
			tags := cs.getInchoateCHLOValues()
			Expect(tags).To(HaveKey(TagSNI))
			Expect(tags[TagPDMD]).To(Equal([]byte("X509")))
		})

		It("is longer than the miminum client hello size", func() {
			err := cs.sendInchoateCHLO()
			Expect(err).ToNot(HaveOccurred())
			Expect(cs.cryptoStream.(*mockStream).dataWritten.Len()).To(BeNumerically(">", protocol.ClientHelloMinimumSize))
		})
	})
})
