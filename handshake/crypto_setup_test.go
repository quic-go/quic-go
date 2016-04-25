package handshake

import (
	"bytes"
	"errors"

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

func (m *mockAEAD) Seal(packetNumber protocol.PacketNumber, associatedData []byte, plaintext []byte) []byte {
	if m.forwardSecure {
		return []byte("forward secure encrypted")
	}
	return []byte("encrypted")
}

func (m *mockAEAD) Open(packetNumber protocol.PacketNumber, associatedData []byte, ciphertext []byte) ([]byte, error) {
	if m.forwardSecure && string(ciphertext) == "forward secure encrypted" {
		return []byte("decrypted"), nil
	} else if !m.forwardSecure && string(ciphertext) == "encrypted" {
		return []byte("decrypted"), nil
	}
	return nil, errors.New("authentication failed")
}

func mockKeyDerivation(forwardSecure bool, sharedSecret, nonces []byte, connID protocol.ConnectionID, chlo []byte, scfg []byte, cert []byte) (crypto.AEAD, error) {
	return &mockAEAD{forwardSecure: forwardSecure}, nil
}

type mockStream struct {
	dataToRead  bytes.Buffer
	dataWritten bytes.Buffer
}

func (s *mockStream) Read(p []byte) (int, error) {
	return s.dataToRead.Read(p)
}

func (s *mockStream) ReadByte() (byte, error) {
	return s.dataToRead.ReadByte()
}

func (s *mockStream) Write(p []byte) (int, error) {
	return s.dataWritten.Write(p)
}

func (s *mockStream) Close() error {
	panic("not implemented")
}

var _ = Describe("Crypto setup", func() {
	var (
		kex    *mockKEX
		signer *mockSigner
		scfg   *ServerConfig
		cs     *CryptoSetup
		stream *mockStream
	)

	BeforeEach(func() {
		stream = &mockStream{}
		kex = &mockKEX{}
		signer = &mockSigner{}
		scfg = NewServerConfig(kex, signer)
		v := protocol.SupportedVersions[len(protocol.SupportedVersions)-1]
		cs = NewCryptoSetup(protocol.ConnectionID(42), v, scfg, stream)
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

		It("handles long handshake", func() {
			WriteHandshakeMessage(&stream.dataToRead, TagCHLO, map[Tag][]byte{})
			WriteHandshakeMessage(&stream.dataToRead, TagCHLO, map[Tag][]byte{TagSCID: scfg.ID, TagSNO: cs.nonce})
			cs.HandleCryptoStream()
			Expect(stream.dataWritten.Bytes()).To(HavePrefix("REJ"))
			Expect(stream.dataWritten.Bytes()).To(ContainSubstring("SHLO"))
		})

		It("handles 0-RTT handshake", func() {
			WriteHandshakeMessage(&stream.dataToRead, TagCHLO, map[Tag][]byte{TagSCID: scfg.ID, TagSNO: cs.nonce})
			cs.HandleCryptoStream()
			Expect(stream.dataWritten.Bytes()).To(HavePrefix("SHLO"))
			Expect(stream.dataWritten.Bytes()).ToNot(ContainSubstring("REJ"))
		})

		It("recognizes inchoate CHLOs missing SCID", func() {
			Expect(cs.isInchoateCHLO(map[Tag][]byte{TagSNO: cs.nonce})).To(BeTrue())
		})

		It("recognizes inchoate CHLOs missing SNO", func() {
			Expect(cs.isInchoateCHLO(map[Tag][]byte{TagSCID: scfg.ID})).To(BeTrue())
		})

		It("recognizes proper CHLOs", func() {
			Expect(cs.isInchoateCHLO(map[Tag][]byte{TagSCID: scfg.ID, TagSNO: cs.nonce})).To(BeFalse())
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
				Expect(cs.Seal(0, []byte{}, []byte("foobar"))).To(Equal(foobarFNVSigned))
			})

			It("is accepted initially", func() {
				d, err := cs.Open(0, []byte{}, foobarFNVSigned)
				Expect(err).ToNot(HaveOccurred())
				Expect(d).To(Equal([]byte("foobar")))
			})

			It("is not accepted after CHLO", func() {
				doCHLO()
				Expect(cs.secureAEAD).ToNot(BeNil())
				_, err := cs.Open(0, []byte{}, foobarFNVSigned)
				Expect(err).To(MatchError("authentication failed"))
			})

			It("is not used after CHLO", func() {
				doCHLO()
				d := cs.Seal(0, []byte{}, []byte("foobar"))
				Expect(d).ToNot(Equal(foobarFNVSigned))
			})
		})

		Context("initial encryption", func() {
			It("is used after CHLO", func() {
				doCHLO()
				d := cs.Seal(0, []byte{}, []byte("foobar"))
				Expect(d).To(Equal([]byte("encrypted")))
			})

			It("is accepted after CHLO", func() {
				doCHLO()
				d, err := cs.Open(0, []byte{}, []byte("encrypted"))
				Expect(err).ToNot(HaveOccurred())
				Expect(d).To(Equal([]byte("decrypted")))
			})

			It("is not used after receiving forward secure packet", func() {
				doCHLO()
				_, err := cs.Open(0, []byte{}, []byte("forward secure encrypted"))
				Expect(err).ToNot(HaveOccurred())
				d := cs.Seal(0, []byte{}, []byte("foobar"))
				Expect(d).To(Equal([]byte("forward secure encrypted")))
			})

			It("is not accepted after receiving forward secure packet", func() {
				doCHLO()
				_, err := cs.Open(0, []byte{}, []byte("forward secure encrypted"))
				Expect(err).ToNot(HaveOccurred())
				_, err = cs.Open(0, []byte{}, []byte("encrypted"))
				Expect(err).To(MatchError("authentication failed"))
			})
		})

		Context("forward secure encryption", func() {
			It("is used after receiving forward secure packet", func() {
				doCHLO()
				_, err := cs.Open(0, []byte{}, []byte("forward secure encrypted"))
				Expect(err).ToNot(HaveOccurred())
				d := cs.Seal(0, []byte{}, []byte("foobar"))
				Expect(d).To(Equal([]byte("forward secure encrypted")))
			})
		})
	})
})
