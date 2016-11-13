package handshake

import (
	"bytes"
	"encoding/binary"
	"time"

	"github.com/lucas-clemente/quic-go/crypto"
	"github.com/lucas-clemente/quic-go/protocol"
	"github.com/lucas-clemente/quic-go/qerr"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

type mockCertManager struct {
	setDataCalledWith []byte
	leafCert          []byte
}

func (m *mockCertManager) SetData(data []byte) error {
	m.setDataCalledWith = data
	return nil
}

func (m *mockCertManager) GetLeafCert() []byte {
	return m.leafCert
}

var _ = Describe("Crypto setup", func() {
	var cs *cryptoSetupClient
	var certManager *mockCertManager
	var stream *mockStream

	BeforeEach(func() {
		stream = &mockStream{}
		certManager = &mockCertManager{}
		csInt, err := NewCryptoSetupClient(0, protocol.Version36, stream)
		Expect(err).ToNot(HaveOccurred())
		cs = csInt.(*cryptoSetupClient)
		cs.certManager = certManager
	})

	Context("Reading REJ", func() {
		var tagMap map[Tag][]byte

		BeforeEach(func() {
			tagMap = make(map[Tag][]byte)
		})

		It("rejects handshake messages with the wrong message tag", func() {
			WriteHandshakeMessage(&stream.dataToRead, TagCHLO, tagMap)
			err := cs.HandleCryptoStream()
			Expect(err).To(MatchError(qerr.InvalidCryptoMessageType))
		})

		It("errors on invalid handshake messages", func() {
			b := &bytes.Buffer{}
			WriteHandshakeMessage(b, TagCHLO, tagMap)
			stream.dataToRead.Write(b.Bytes()[:b.Len()-2]) // cut the handshake message
			err := cs.HandleCryptoStream()
			// note that if this was a complete handshake message, HandleCryptoStream would fail with a qerr.InvalidCryptoMessageType
			Expect(err).To(MatchError(qerr.HandshakeFailed))
		})

		It("passes the message on for parsing, and reads the source address token", func() {
			stk := []byte("foobar")
			tagMap[TagSTK] = stk
			WriteHandshakeMessage(&stream.dataToRead, TagREJ, tagMap)
			// this will throw a qerr.HandshakeFailed due to an EOF in WriteHandshakeMessage
			// this is because the mockStream doesn't block if there's no data to read
			err := cs.HandleCryptoStream()
			Expect(err).To(MatchError(qerr.HandshakeFailed))
			Expect(cs.stk).Should(Equal(stk))
		})

		It("saves the server nonce", func() {
			nonc := []byte("servernonce")
			tagMap[TagSNO] = nonc
			err := cs.handleREJMessage(tagMap)
			Expect(err).ToNot(HaveOccurred())
			Expect(cs.sno).To(Equal(nonc))
		})

		It("passes the certificates to the CertManager", func() {
			tagMap[TagCERT] = []byte("cert")
			err := cs.handleREJMessage(tagMap)
			Expect(err).ToNot(HaveOccurred())
			Expect(certManager.setDataCalledWith).To(Equal(tagMap[TagCERT]))
		})

		Context("Reading server configs", func() {
			It("reads a server config", func() {
				b := &bytes.Buffer{}
				scfg := getDefaultServerConfigClient()
				WriteHandshakeMessage(b, TagSCFG, scfg)
				tagMap[TagSCFG] = b.Bytes()
				err := cs.handleREJMessage(tagMap)
				Expect(err).ToNot(HaveOccurred())
				Expect(cs.serverConfig).ToNot(BeNil())
				Expect(cs.serverConfig.ID).To(Equal(scfg[TagSCID]))
			})

			It("generates a client nonce after reading a server config", func() {
				b := &bytes.Buffer{}
				WriteHandshakeMessage(b, TagSCFG, getDefaultServerConfigClient())
				tagMap[TagSCFG] = b.Bytes()
				err := cs.handleREJMessage(tagMap)
				Expect(err).ToNot(HaveOccurred())
				Expect(cs.nonc).To(HaveLen(32))
			})

			It("only generates a client nonce once, when reading multiple server configs", func() {
				b := &bytes.Buffer{}
				WriteHandshakeMessage(b, TagSCFG, getDefaultServerConfigClient())
				tagMap[TagSCFG] = b.Bytes()
				err := cs.handleREJMessage(tagMap)
				Expect(err).ToNot(HaveOccurred())
				nonc := cs.nonc
				Expect(nonc).ToNot(BeEmpty())
				err = cs.handleREJMessage(tagMap)
				Expect(err).ToNot(HaveOccurred())
				Expect(cs.nonc).To(Equal(nonc))
			})

			It("passes on errors from reading the server config", func() {
				b := &bytes.Buffer{}
				WriteHandshakeMessage(b, TagSHLO, make(map[Tag][]byte))
				tagMap[TagSCFG] = b.Bytes()
				_, origErr := parseServerConfig(b.Bytes())
				err := cs.handleREJMessage(tagMap)
				Expect(err).To(HaveOccurred())
				Expect(err).To(MatchError(origErr))
			})
		})
	})

	Context("Reading SHLO", func() {
		var tagMap map[Tag][]byte

		BeforeEach(func() {
			tagMap = make(map[Tag][]byte)
			tagMap[TagPUBS] = []byte{0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f}
			kex, err := crypto.NewCurve25519KEX()
			Expect(err).ToNot(HaveOccurred())
			serverConfig := &serverConfigClient{
				kex: kex,
			}
			cs.serverConfig = serverConfig
		})

		It("rejects SHLOs without a PUBS", func() {
			delete(tagMap, TagPUBS)
			err := cs.handleSHLOMessage(tagMap)
			Expect(err).To(MatchError(qerr.Error(qerr.CryptoMessageParameterNotFound, "PUBS")))
		})

		It("reads the server nonce, if set", func() {
			tagMap[TagSNO] = []byte("server nonce")
			err := cs.handleSHLOMessage(tagMap)
			Expect(err).ToNot(HaveOccurred())
			Expect(cs.sno).To(Equal(tagMap[TagSNO]))
		})

		It("creates a forwardSecureAEAD", func() {
			tagMap[TagSNO] = []byte("server nonce")
			err := cs.handleSHLOMessage(tagMap)
			Expect(err).ToNot(HaveOccurred())
			Expect(cs.forwardSecureAEAD).ToNot(BeNil())
		})
	})

	Context("CHLO generation", func() {
		It("is longer than the miminum client hello size", func() {
			err := cs.sendCHLO()
			Expect(err).ToNot(HaveOccurred())
			Expect(cs.cryptoStream.(*mockStream).dataWritten.Len()).To(BeNumerically(">", protocol.ClientHelloMinimumSize))
		})

		It("doesn't overflow the packet with padding", func() {
			tagMap := make(map[Tag][]byte)
			tagMap[TagSCID] = bytes.Repeat([]byte{0}, protocol.ClientHelloMinimumSize*6/10)
			cs.addPadding(tagMap)
			Expect(len(tagMap[TagPAD])).To(BeNumerically("<", protocol.ClientHelloMinimumSize/2))
		})

		It("saves the last sent CHLO", func() {
			// send first CHLO
			err := cs.sendCHLO()
			Expect(err).ToNot(HaveOccurred())
			Expect(cs.cryptoStream.(*mockStream).dataWritten.Bytes()).To(Equal(cs.lastSentCHLO))
			cs.cryptoStream.(*mockStream).dataWritten.Reset()
			firstCHLO := cs.lastSentCHLO
			// send second CHLO
			cs.sno = []byte("foobar")
			err = cs.sendCHLO()
			Expect(err).ToNot(HaveOccurred())
			Expect(cs.cryptoStream.(*mockStream).dataWritten.Bytes()).To(Equal(cs.lastSentCHLO))
			Expect(cs.lastSentCHLO).ToNot(Equal(firstCHLO))
		})

		It("has the right values for an inchoate CHLO", func() {
			tags := cs.getTags()
			Expect(tags).To(HaveKey(TagSNI))
			Expect(tags[TagPDMD]).To(Equal([]byte("X509")))
			Expect(tags[TagVER]).To(Equal([]byte("Q036")))
		})

		It("includes the server config id, if available", func() {
			id := []byte("foobar")
			cs.serverConfig = &serverConfigClient{ID: id}
			tags := cs.getTags()
			Expect(tags[TagSCID]).To(Equal(id))
		})

		It("includes the source address token, if available", func() {
			cs.stk = []byte("sourceaddresstoken")
			tags := cs.getTags()
			Expect(tags[TagSTK]).To(Equal(cs.stk))
		})

		It("includes the server nonce, if available", func() {
			cs.sno = []byte("foobar")
			tags := cs.getTags()
			Expect(tags[TagSNO]).To(Equal(cs.sno))
		})

		It("doesn't include optional values, if not available", func() {
			tags := cs.getTags()
			Expect(tags).ToNot(HaveKey(TagSCID))
			Expect(tags).ToNot(HaveKey(TagSNO))
			Expect(tags).ToNot(HaveKey(TagSTK))
		})

		It("doesn't change any values after reading the certificate, if the server config is missing", func() {
			tags := cs.getTags()
			certManager.leafCert = []byte("leafcert")
			Expect(cs.getTags()).To(Equal(tags))
		})

		It("sends a client nonce and a public value after reading the certificate and the server config", func() {
			certManager.leafCert = []byte("leafcert")
			cs.nonc = []byte("client-nonce")
			kex, err := crypto.NewCurve25519KEX()
			Expect(err).ToNot(HaveOccurred())
			cs.serverConfig = &serverConfigClient{kex: kex}
			tags := cs.getTags()
			Expect(tags[TagNONC]).To(Equal(cs.nonc))
			Expect(tags[TagPUBS]).To(Equal(kex.PublicKey()))
		})
	})

	Context("escalating crypto", func() {
		// sets all values necessary for escalating to secureAEAD
		BeforeEach(func() {
			kex, err := crypto.NewCurve25519KEX()
			Expect(err).ToNot(HaveOccurred())
			cs.serverConfig = &serverConfigClient{
				kex:          kex,
				obit:         []byte("obit"),
				sharedSecret: []byte("sharedSecret"),
				raw:          []byte("rawserverconfig"),
			}
			cs.lastSentCHLO = []byte("lastSentCHLO")
			cs.nonc = []byte("nonc")
			cs.diversificationNonce = []byte("divnonce")
			certManager.leafCert = []byte("leafCert")
		})

		It("creates a secureAEAD once it has all necessary values", func() {
			err := cs.maybeUpgradeCrypto()
			Expect(err).ToNot(HaveOccurred())
			Expect(cs.secureAEAD).ToNot(BeNil())
		})

		It("tries to escalate before reading a handshake message", func() {
			Expect(cs.secureAEAD).To(BeNil())
			err := cs.HandleCryptoStream()
			// this will throw a qerr.HandshakeFailed due to an EOF in WriteHandshakeMessage
			// this is because the mockStream doesn't block if there's no data to read
			Expect(err).To(MatchError(qerr.HandshakeFailed))
			Expect(cs.secureAEAD).ToNot(BeNil())
		})

		It("tries to escalate the crypto after receiving a diversification nonce", func() {
			cs.diversificationNonce = nil
			Expect(cs.secureAEAD).To(BeNil())
			err := cs.SetDiversificationNonce([]byte("div"))
			Expect(err).ToNot(HaveOccurred())
			Expect(cs.secureAEAD).ToNot(BeNil())
		})
	})

	Context("Diversification Nonces", func() {
		It("sets a diversification nonce", func() {
			nonce := []byte("foobar")
			err := cs.SetDiversificationNonce(nonce)
			Expect(err).ToNot(HaveOccurred())
			Expect(cs.diversificationNonce).To(Equal(nonce))
		})

		It("doesn't do anything when called multiple times with the same nonce", func() {
			nonce := []byte("foobar")
			err := cs.SetDiversificationNonce(nonce)
			Expect(err).ToNot(HaveOccurred())
			err = cs.SetDiversificationNonce(nonce)
			Expect(err).ToNot(HaveOccurred())
			Expect(cs.diversificationNonce).To(Equal(nonce))
		})

		It("rejects a different diversification nonce", func() {
			nonce1 := []byte("foobar")
			nonce2 := []byte("raboof")
			err := cs.SetDiversificationNonce(nonce1)
			Expect(err).ToNot(HaveOccurred())
			err = cs.SetDiversificationNonce(nonce2)
			Expect(err).To(MatchError(errConflictingDiversificationNonces))
		})
	})

	Context("Client Nonce generation", func() {
		BeforeEach(func() {
			cs.serverConfig = &serverConfigClient{}
			cs.serverConfig.obit = []byte{0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8}
		})

		It("generates a client nonce", func() {
			now := time.Now()
			err := cs.generateClientNonce()
			Expect(cs.nonc).To(HaveLen(32))
			Expect(err).ToNot(HaveOccurred())
			Expect(time.Unix(int64(binary.BigEndian.Uint32(cs.nonc[0:4])), 0)).To(BeTemporally("~", now, 1*time.Second))
			Expect(cs.nonc[4:12]).To(Equal(cs.serverConfig.obit))
		})

		It("uses random values for the last 20 bytes", func() {
			err := cs.generateClientNonce()
			Expect(err).ToNot(HaveOccurred())
			nonce1 := cs.nonc
			cs.nonc = []byte{}
			err = cs.generateClientNonce()
			Expect(err).ToNot(HaveOccurred())
			nonce2 := cs.nonc
			Expect(nonce1[4:12]).To(Equal(nonce2[4:12]))
			Expect(nonce1[12:]).ToNot(Equal(nonce2[12:]))
		})

		It("errors if a client nonce has already been generated", func() {
			err := cs.generateClientNonce()
			Expect(err).ToNot(HaveOccurred())
			err = cs.generateClientNonce()
			Expect(err).To(MatchError(errClientNonceAlreadyExists))
		})

		It("errors if no OBIT value is available", func() {
			cs.serverConfig.obit = []byte{}
			err := cs.generateClientNonce()
			Expect(err).To(MatchError(errNoObitForClientNonce))
		})
	})
})
