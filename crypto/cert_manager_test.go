package crypto

import (
	"github.com/lucas-clemente/quic-go/qerr"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Cert Manager", func() {
	var cm *certManager

	BeforeEach(func() {
		cm = NewCertManager().(*certManager)
	})

	It("errors when given invalid data", func() {
		err := cm.SetData([]byte("foobar"))
		Expect(err).To(MatchError(qerr.Error(qerr.InvalidCryptoMessageParameter, "Certificate data invalid")))
	})

	It("decompresses a certificate chain", func() {
		cert1 := []byte{0xde, 0xca, 0xfb, 0xad}
		cert2 := []byte{0xde, 0xad, 0xbe, 0xef, 0x13, 0x37}
		chain := [][]byte{cert1, cert2}
		compressed, err := compressChain(chain, nil, nil)
		Expect(err).ToNot(HaveOccurred())
		err = cm.SetData(compressed)
		Expect(err).ToNot(HaveOccurred())
		Expect(cm.chain).To(Equal(chain))
	})

	Context("getting the leaf cert", func() {
		It("gets it", func() {
			cert1 := []byte{0xc1}
			cert2 := []byte{0xc2}
			cm.chain = [][]byte{cert1, cert2}
			leafCert := cm.GetLeafCert()
			Expect(leafCert).To(Equal(cert1))
		})

		It("returns nil if the chain hasn't been set yet", func() {
			leafCert := cm.GetLeafCert()
			Expect(leafCert).To(BeNil())
		})
	})

	Context("verifying the server signature", func() {
		It("errors when the chain hasn't been set yet", func() {
			valid, err := cm.VerifyServerProof([]byte("proof"), []byte("chlo"), []byte("scfg"))
			Expect(err).To(MatchError(errNoCertificateChain))
			Expect(valid).To(BeFalse())
		})

		It("errors when it can't parse the certificate", func() {
			cert := []byte("invalid cert")
			cm.chain = [][]byte{cert}
			valid, err := cm.VerifyServerProof([]byte("proof"), []byte("chlo"), []byte("scfg"))
			Expect(err).To(HaveOccurred())
			Expect(err).ToNot(MatchError(errNoCertificateChain))
			Expect(valid).To(BeFalse())
		})
	})
})
