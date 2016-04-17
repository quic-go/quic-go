package handshake

import (
	"bytes"
	"errors"
	"io"
	"io/ioutil"

	"github.com/lucas-clemente/quic-go/crypto"
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

type mockAEAD struct {
	forwardSecure bool
}

func (m *mockAEAD) Seal(packetNumber protocol.PacketNumber, b *bytes.Buffer, associatedData []byte, plaintext []byte) {
	if m.forwardSecure {
		b.Write([]byte("forward secure encrypted"))
	} else {
		b.Write([]byte("encrypted"))
	}
}

func (m *mockAEAD) Open(packetNumber protocol.PacketNumber, associatedData []byte, ciphertext io.Reader) (*bytes.Reader, error) {
	data, _ := ioutil.ReadAll(ciphertext)
	if m.forwardSecure && string(data) == "forward secure encrypted" {
		return bytes.NewReader([]byte("decrypted")), nil
	} else if !m.forwardSecure && string(data) == "encrypted" {
		return bytes.NewReader([]byte("decrypted")), nil
	}
	return nil, errors.New("authentication failed")
}

func mockKeyDerivation(forwardSecure bool, sharedSecret, nonces []byte, connID protocol.ConnectionID, chlo []byte, scfg []byte, cert []byte) (crypto.AEAD, error) {
	return &mockAEAD{forwardSecure: forwardSecure}, nil
}

var _ = Describe("Crypto setup", func() {
	var (
		kex    *mockKEX
		signer *mockSigner
		scfg   *ServerConfig
		cs     *CryptoSetup
		buf    *bytes.Buffer
	)

	BeforeEach(func() {
		buf = &bytes.Buffer{}
		kex = &mockKEX{}
		signer = &mockSigner{}
		scfg = NewServerConfig(kex, signer)
		v := protocol.SupportedVersions[len(protocol.SupportedVersions)-1]
		cs = NewCryptoSetup(protocol.ConnectionID(42), v, scfg)
		cs.keyDerivation = mockKeyDerivation
	})

	It("has a nonce", func() {
		Expect(cs.nonce).To(HaveLen(32))
		s := 0
		for _, b := range cs.nonce {
			s += int(b)
		}
		Expect(s).ToNot(BeZero())
	})

	Context("when responding to client messages", func() {
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
			WriteHandshakeMessage(buf, TagCHLO, map[Tag][]byte{TagSCID: scfg.ID})
			response, err := cs.HandleCryptoMessage(buf.Bytes())
			Expect(err).ToNot(HaveOccurred())
			Expect(response).To(HavePrefix("SHLO"))
		})

		It("recognizes missing SCID", func() {
			WriteHandshakeMessage(buf, TagCHLO, map[Tag][]byte{})
			response, err := cs.HandleCryptoMessage(buf.Bytes())
			Expect(err).ToNot(HaveOccurred())
			Expect(response).To(HavePrefix("REJ"))
		})
	})

	Context("escalating crypto", func() {
		foobarFNVSigned := []byte{0x18, 0x6f, 0x44, 0xba, 0x97, 0x35, 0xd, 0x6f, 0xbf, 0x64, 0x3c, 0x79, 0x66, 0x6f, 0x6f, 0x62, 0x61, 0x72}

		doCHLO := func() {
			_, err := cs.handleCHLO([]byte("chlo-data"), map[Tag][]byte{TagPUBS: []byte("pubs-c")})
			Expect(err).ToNot(HaveOccurred())
		}

		Context("null encryption", func() {
			It("is used initially", func() {
				cs.Seal(0, buf, []byte{}, []byte("foobar"))
				Expect(buf.Bytes()).To(Equal(foobarFNVSigned))
			})

			It("is accepted initially", func() {
				r, err := cs.Open(0, []byte{}, bytes.NewReader(foobarFNVSigned))
				Expect(err).ToNot(HaveOccurred())
				d, err := ioutil.ReadAll(r)
				Expect(err).ToNot(HaveOccurred())
				Expect(d).To(Equal([]byte("foobar")))
			})

			It("is not accepted after CHLO", func() {
				doCHLO()
				Expect(cs.secureAEAD).ToNot(BeNil())
				_, err := cs.Open(0, []byte{}, bytes.NewReader(foobarFNVSigned))
				Expect(err).To(MatchError("authentication failed"))
			})

			It("is not used after CHLO", func() {
				doCHLO()
				cs.Seal(0, buf, []byte{}, []byte("foobar"))
				Expect(buf.Bytes()).ToNot(Equal(foobarFNVSigned))
			})
		})

		Context("initial encryption", func() {
			It("is used after CHLO", func() {
				doCHLO()
				cs.Seal(0, buf, []byte{}, []byte("foobar"))
				Expect(buf.Bytes()).To(Equal([]byte("encrypted")))
			})

			It("is accepted after CHLO", func() {
				doCHLO()
				r, err := cs.Open(0, []byte{}, bytes.NewReader([]byte("encrypted")))
				Expect(err).ToNot(HaveOccurred())
				d, err := ioutil.ReadAll(r)
				Expect(err).ToNot(HaveOccurred())
				Expect(d).To(Equal([]byte("decrypted")))
			})

			It("is not used after receiving forward secure packet", func() {
				doCHLO()
				_, err := cs.Open(0, []byte{}, bytes.NewReader([]byte("forward secure encrypted")))
				Expect(err).ToNot(HaveOccurred())
				cs.Seal(0, buf, []byte{}, []byte("foobar"))
				Expect(buf.Bytes()).To(Equal([]byte("forward secure encrypted")))
			})

			It("is not accepted after receiving forward secure packet", func() {
				doCHLO()
				_, err := cs.Open(0, []byte{}, bytes.NewReader([]byte("forward secure encrypted")))
				Expect(err).ToNot(HaveOccurred())
				_, err = cs.Open(0, []byte{}, bytes.NewReader([]byte("encrypted")))
				Expect(err).To(MatchError("authentication failed"))
			})
		})

		Context("forward secure encryption", func() {
			It("is used after receiving forward secure packet", func() {
				doCHLO()
				_, err := cs.Open(0, []byte{}, bytes.NewReader([]byte("forward secure encrypted")))
				Expect(err).ToNot(HaveOccurred())
				cs.Seal(0, buf, []byte{}, []byte("foobar"))
				Expect(buf.Bytes()).To(Equal([]byte("forward secure encrypted")))
			})
		})
	})
})
