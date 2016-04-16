package handshake

import (
	"bytes"

	"github.com/lucas-clemente/quic-go/protocol"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

type mockKEX struct{}

func (*mockKEX) PublicKey() []byte {
	return []byte("pubs-s")
}
func (*mockKEX) CalculateSharedKey(otherPublic []byte) ([]byte, error) {
	return []byte("shared key"), nil
}

type mockSigner struct {
	gotCHLO bool
}

func (s *mockSigner) SignServerProof(chlo []byte, serverConfigData []byte) ([]byte, error) {
	if len(chlo) > 0 {
		s.gotCHLO = true
	}
	return []byte("proof"), nil
}
func (*mockSigner) GetCertCompressed() []byte {
	return []byte("certcompressed")
}
func (*mockSigner) GetCertUncompressed() []byte {
	return []byte("certuncompressed")
}

var _ = Describe("Crypto setup", func() {
	var (
		kex    *mockKEX
		signer *mockSigner
		scfg   *ServerConfig
		cs     *CryptoSetup
	)

	BeforeEach(func() {
		kex = &mockKEX{}
		signer = &mockSigner{}
		scfg = NewServerConfig(kex, signer)
		v := protocol.SupportedVersions[len(protocol.SupportedVersions)-1]
		cs = NewCryptoSetup(protocol.ConnectionID(42), v, scfg)
	})

	It("has a nonce", func() {
		Expect(cs.nonce).To(HaveLen(32))
		Expect(cs.nonce[10]).ToNot(BeZero())
	})

	It("generates REJ messages", func() {
		response, err := cs.handleInchoateCHLO([]byte("chlo"))
		Expect(err).ToNot(HaveOccurred())
		Expect(response).To(HavePrefix("REJ"))
		Expect(response).To(ContainSubstring("certcompressed"))
		Expect(response).To(ContainSubstring("pubs-s"))
		Expect(signer.gotCHLO).To(BeTrue())
	})

	It("generates REJ messages for version 30", func() {
		cs.version = protocol.VersionNumber(30)
		_, err := cs.handleInchoateCHLO(sampleCHLO)
		Expect(err).ToNot(HaveOccurred())
		Expect(signer.gotCHLO).To(BeFalse())
	})

	It("generates SHLO messages", func() {
		response, err := cs.handleCHLO([]byte("chlo-data"), map[Tag][]byte{
			TagPUBS: []byte("pubs-c"),
		})
		Expect(err).ToNot(HaveOccurred())
		Expect(response).To(HavePrefix("SHLO"))
		Expect(response).To(ContainSubstring("pubs-s")) // TODO: Should be new pubs
		Expect(response).To(ContainSubstring(string(cs.nonce)))
		Expect(response).To(ContainSubstring(string(protocol.SupportedVersionsAsTags)))
		Expect(cs.secureAEAD).ToNot(BeNil())
		Expect(cs.forwardSecureAEAD).ToNot(BeNil())
	})

	It("recognizes SCID", func() {
		var data bytes.Buffer
		WriteHandshakeMessage(&data, TagCHLO, map[Tag][]byte{TagSCID: scfg.ID})
		response, err := cs.HandleCryptoMessage(data.Bytes())
		Expect(err).ToNot(HaveOccurred())
		Expect(response).To(HavePrefix("SHLO"))
	})

	It("recognizes missing SCID", func() {
		var data bytes.Buffer
		WriteHandshakeMessage(&data, TagCHLO, map[Tag][]byte{})
		response, err := cs.HandleCryptoMessage(data.Bytes())
		Expect(err).ToNot(HaveOccurred())
		Expect(response).To(HavePrefix("REJ"))
	})
})
