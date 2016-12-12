package handshake

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/lucas-clemente/quic-go/crypto"
	"github.com/lucas-clemente/quic-go/protocol"
	"github.com/lucas-clemente/quic-go/qerr"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

// taken from https://golang.org/src/crypto/tls/generate_cert.go
func pemBlockForKey(priv interface{}) *pem.Block {
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		return &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)}
	case *ecdsa.PrivateKey:
		b, err := x509.MarshalECPrivateKey(k)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Unable to marshal ECDSA private key: %v", err)
			os.Exit(2)
		}
		return &pem.Block{Type: "EC PRIVATE KEY", Bytes: b}
	default:
		return nil
	}
}

func pemBlockForCert(certDER []byte) *pem.Block {
	return &pem.Block{Type: "CERTIFICATE", Bytes: certDER}
}

type keyDerivationValues struct {
	forwardSecure bool
	sharedSecret  []byte
	nonces        []byte
	connID        protocol.ConnectionID
	chlo          []byte
	scfg          []byte
	cert          []byte
	divNonce      []byte
	pers          protocol.Perspective
}

type mockCertManager struct {
	setDataCalledWith []byte
	setDataError      error

	commonCertificateHashes []byte

	leafCert          []byte
	leafCertHash      uint64
	leafCertHashError error

	verifyServerProofResult bool
	verifyServerProofCalled bool

	verifyError  error
	verifyCalled bool
}

func (m *mockCertManager) SetData(data []byte) error {
	m.setDataCalledWith = data
	return m.setDataError
}

func (m *mockCertManager) GetCommonCertificateHashes() []byte {
	return m.commonCertificateHashes
}

func (m *mockCertManager) GetLeafCert() []byte {
	return m.leafCert
}

func (m *mockCertManager) GetLeafCertHash() (uint64, error) {
	return m.leafCertHash, m.leafCertHashError
}

func (m *mockCertManager) VerifyServerProof(proof, chlo, serverConfigData []byte) bool {
	m.verifyServerProofCalled = true
	return m.verifyServerProofResult
}

func (m *mockCertManager) Verify(hostname string) error {
	m.verifyCalled = true
	return m.verifyError
}

var _ = Describe("Crypto setup", func() {
	var cs *cryptoSetupClient
	var certManager *mockCertManager
	var stream *mockStream
	var keyDerivationCalledWith *keyDerivationValues

	BeforeEach(func() {
		keyDerivation := func(forwardSecure bool, sharedSecret, nonces []byte, connID protocol.ConnectionID, chlo []byte, scfg []byte, cert []byte, divNonce []byte, pers protocol.Perspective) (crypto.AEAD, error) {
			keyDerivationCalledWith = &keyDerivationValues{
				forwardSecure: forwardSecure,
				sharedSecret:  sharedSecret,
				nonces:        nonces,
				connID:        connID,
				chlo:          chlo,
				scfg:          scfg,
				cert:          cert,
				divNonce:      divNonce,
				pers:          pers,
			}
			return crypto.DeriveKeysAESGCM(forwardSecure, sharedSecret, nonces, connID, chlo, scfg, cert, divNonce, pers)
		}

		stream = &mockStream{}
		certManager = &mockCertManager{}
		version := protocol.Version36
		csInt, err := NewCryptoSetupClient("hostname", 0, version, stream, NewConnectionParamatersManager(protocol.PerspectiveClient, version), make(chan struct{}, 1))
		Expect(err).ToNot(HaveOccurred())
		cs = csInt.(*cryptoSetupClient)
		cs.certManager = certManager
		cs.keyDerivation = keyDerivation
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

		It("saves the proof", func() {
			proof := []byte("signature for the server config")
			tagMap[TagPROF] = proof
			err := cs.handleREJMessage(tagMap)
			Expect(err).ToNot(HaveOccurred())
			Expect(cs.proof).To(Equal(proof))
		})

		It("saves the last sent CHLO for signature validation, when receiving the proof", func() {
			chlo := []byte("last sent CHLO")
			cs.lastSentCHLO = chlo
			err := cs.handleREJMessage(tagMap)
			Expect(err).ToNot(HaveOccurred())
			Expect(cs.chloForSignature).To(BeEmpty())
			tagMap[TagPROF] = []byte("signature")
			err = cs.handleREJMessage(tagMap)
			Expect(err).ToNot(HaveOccurred())
			Expect(cs.chloForSignature).To(Equal(chlo))
		})

		It("saves the server nonce", func() {
			nonc := []byte("servernonce")
			tagMap[TagSNO] = nonc
			err := cs.handleREJMessage(tagMap)
			Expect(err).ToNot(HaveOccurred())
			Expect(cs.sno).To(Equal(nonc))
		})

		Context("Certificates", func() {
			BeforeEach(func() {
				cs.serverConfig = &serverConfigClient{}
			})

			It("passes the certificates to the CertManager", func() {
				tagMap[TagCERT] = []byte("cert")
				err := cs.handleREJMessage(tagMap)
				Expect(err).ToNot(HaveOccurred())
				Expect(certManager.setDataCalledWith).To(Equal(tagMap[TagCERT]))
			})

			It("returns an InvalidCryptoMessageParameter error if it can't parse the cert chain", func() {
				tagMap[TagCERT] = []byte("cert")
				certManager.setDataError = errors.New("can't parse")
				err := cs.handleREJMessage(tagMap)
				Expect(err).To(MatchError(qerr.Error(qerr.InvalidCryptoMessageParameter, "Certificate data invalid")))
			})

			Context("verifying the certificate chain", func() {
				It("returns a ProofInvalid error if the certificate chain is not valid", func() {
					tagMap[TagCERT] = []byte("cert")
					certManager.verifyError = errors.New("invalid")
					err := cs.handleREJMessage(tagMap)
					Expect(err).To(MatchError(qerr.ProofInvalid))
				})

				It("verifies the certificate", func() {
					certManager.verifyServerProofResult = true
					tagMap[TagCERT] = []byte("cert")
					err := cs.handleREJMessage(tagMap)
					Expect(err).ToNot(HaveOccurred())
					Expect(certManager.verifyCalled).To(BeTrue())
				})
			})

			Context("verifying the signature", func() {
				BeforeEach(func() {
					tagMap[TagCERT] = []byte("cert")
					tagMap[TagPROF] = []byte("proof")
					certManager.leafCert = []byte("leafcert")
				})

				It("rejects wrong signature", func() {
					certManager.verifyServerProofResult = false
					err := cs.handleREJMessage(tagMap)
					Expect(err).To(MatchError(qerr.ProofInvalid))
					Expect(certManager.verifyServerProofCalled).To(BeTrue())
				})

				It("accepts correct signatures", func() {
					certManager.verifyServerProofResult = true
					err := cs.handleREJMessage(tagMap)
					Expect(err).ToNot(HaveOccurred())
					Expect(certManager.verifyServerProofCalled).To(BeTrue())
				})

				It("doesn't try to verify the signature if the certificate is missing", func() {
					delete(tagMap, TagCERT)
					certManager.leafCert = nil
					err := cs.handleREJMessage(tagMap)
					Expect(err).ToNot(HaveOccurred())
					Expect(certManager.verifyServerProofCalled).To(BeFalse())
				})

				It("doesn't try to verify the signature if the server config is missing", func() {
					cs.serverConfig = nil
					err := cs.handleREJMessage(tagMap)
					Expect(err).ToNot(HaveOccurred())
					Expect(certManager.verifyServerProofCalled).To(BeFalse())
				})

				It("doesn't try to verify the signature if the signature is missing", func() {
					delete(tagMap, TagPROF)
					err := cs.handleREJMessage(tagMap)
					Expect(err).ToNot(HaveOccurred())
					Expect(certManager.verifyServerProofCalled).To(BeFalse())
				})
			})
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

			It("rejects expired server configs", func() {
				b := &bytes.Buffer{}
				scfg := getDefaultServerConfigClient()
				scfg[TagEXPY] = []byte{0x80, 0x54, 0x72, 0x4F, 0, 0, 0, 0} // 2012-03-28
				WriteHandshakeMessage(b, TagSCFG, scfg)
				tagMap[TagSCFG] = b.Bytes()
				// make sure we actually set TagEXPY correct
				serverConfig, err := parseServerConfig(b.Bytes())
				Expect(err).ToNot(HaveOccurred())
				Expect(serverConfig.expiry.Year()).To(Equal(2012))
				// now try to read this server config in the crypto setup
				err = cs.handleREJMessage(tagMap)
				Expect(err).To(MatchError(qerr.CryptoServerConfigExpired))
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
			tagMap = map[Tag][]byte{
				TagPUBS: []byte{0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f},
				TagVER:  protocol.SupportedVersionsAsTags,
			}
			kex, err := crypto.NewCurve25519KEX()
			Expect(err).ToNot(HaveOccurred())
			serverConfig := &serverConfigClient{
				kex: kex,
			}
			cs.serverConfig = serverConfig
			cs.receivedSecurePacket = true
		})

		It("rejects unencrypted SHLOs", func() {
			cs.receivedSecurePacket = false
			err := cs.handleSHLOMessage(tagMap)
			Expect(err).To(MatchError(qerr.Error(qerr.CryptoEncryptionLevelIncorrect, "unencrypted SHLO message")))
			Expect(cs.HandshakeComplete()).To(BeFalse())
			Expect(cs.aeadChanged).ToNot(Receive())
		})

		It("rejects SHLOs without a PUBS", func() {
			delete(tagMap, TagPUBS)
			err := cs.handleSHLOMessage(tagMap)
			Expect(err).To(MatchError(qerr.Error(qerr.CryptoMessageParameterNotFound, "PUBS")))
			Expect(cs.HandshakeComplete()).To(BeFalse())
		})

		It("rejects SHLOs without a version list", func() {
			delete(tagMap, TagVER)
			err := cs.handleSHLOMessage(tagMap)
			Expect(err).To(MatchError(qerr.Error(qerr.InvalidCryptoMessageParameter, "server hello missing version list")))
			Expect(cs.HandshakeComplete()).To(BeFalse())
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
			Expect(cs.HandshakeComplete()).To(BeTrue())
			Expect(cs.aeadChanged).To(Receive())
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
			cs.hostname = "sni-hostname"
			certManager.commonCertificateHashes = []byte("common certs")
			tags, err := cs.getTags()
			Expect(err).ToNot(HaveOccurred())
			Expect(string(tags[TagSNI])).To(Equal(cs.hostname))
			Expect(tags[TagPDMD]).To(Equal([]byte("X509")))
			Expect(tags[TagVER]).To(Equal([]byte("Q036")))
			Expect(tags[TagCCS]).To(Equal(certManager.commonCertificateHashes))
		})

		It("adds the tags returned from the connectionParametersManager to the CHLO", func() {
			cpmTags, err := cs.connectionParameters.GetCHLOMap()
			Expect(err).ToNot(HaveOccurred())
			Expect(cpmTags).ToNot(BeEmpty())
			tags, err := cs.getTags()
			Expect(err).ToNot(HaveOccurred())
			for t := range cpmTags {
				Expect(tags).To(HaveKey(t))
			}
		})

		It("doesn't send a CCS if there are no common certificate sets available", func() {
			certManager.commonCertificateHashes = nil
			tags, err := cs.getTags()
			Expect(err).ToNot(HaveOccurred())
			Expect(tags).ToNot(HaveKey(TagCCS))
		})

		It("includes the server config id, if available", func() {
			id := []byte("foobar")
			cs.serverConfig = &serverConfigClient{ID: id}
			tags, err := cs.getTags()
			Expect(err).ToNot(HaveOccurred())
			Expect(tags[TagSCID]).To(Equal(id))
		})

		It("includes the source address token, if available", func() {
			cs.stk = []byte("sourceaddresstoken")
			tags, err := cs.getTags()
			Expect(err).ToNot(HaveOccurred())
			Expect(tags[TagSTK]).To(Equal(cs.stk))
		})

		It("includes the server nonce, if available", func() {
			cs.sno = []byte("foobar")
			tags, err := cs.getTags()
			Expect(err).ToNot(HaveOccurred())
			Expect(tags[TagSNO]).To(Equal(cs.sno))
		})

		It("doesn't include optional values, if not available", func() {
			tags, err := cs.getTags()
			Expect(err).ToNot(HaveOccurred())
			Expect(tags).ToNot(HaveKey(TagSCID))
			Expect(tags).ToNot(HaveKey(TagSNO))
			Expect(tags).ToNot(HaveKey(TagSTK))
		})

		It("doesn't change any values after reading the certificate, if the server config is missing", func() {
			tags, err := cs.getTags()
			Expect(err).ToNot(HaveOccurred())
			certManager.leafCert = []byte("leafcert")
			Expect(cs.getTags()).To(Equal(tags))
		})

		It("sends a the values needed for a full CHLO after reading the certificate and the server config", func() {
			certManager.leafCert = []byte("leafcert")
			cs.nonc = []byte("client-nonce")
			kex, err := crypto.NewCurve25519KEX()
			Expect(err).ToNot(HaveOccurred())
			cs.serverConfig = &serverConfigClient{kex: kex}
			xlct := []byte{0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8}
			certManager.leafCertHash = binary.LittleEndian.Uint64(xlct)
			tags, err := cs.getTags()
			Expect(err).ToNot(HaveOccurred())
			Expect(tags[TagNONC]).To(Equal(cs.nonc))
			Expect(tags[TagPUBS]).To(Equal(kex.PublicKey()))
			Expect(tags[TagXLCT]).To(Equal(xlct))
			Expect(tags[TagKEXS]).To(Equal([]byte("C255")))
			Expect(tags[TagAEAD]).To(Equal([]byte("AESG")))
		})

		It("doesn't send more than MaxClientHellos CHLOs", func() {
			Expect(cs.clientHelloCounter).To(BeZero())
			for i := 1; i <= protocol.MaxClientHellos; i++ {
				err := cs.sendCHLO()
				Expect(err).ToNot(HaveOccurred())
				Expect(cs.clientHelloCounter).To(Equal(i))
			}
			err := cs.sendCHLO()
			Expect(err).To(MatchError(qerr.Error(qerr.CryptoTooManyRejects, fmt.Sprintf("More than %d rejects", protocol.MaxClientHellos))))
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
			cs.serverVerified = true
			err := cs.maybeUpgradeCrypto()
			Expect(err).ToNot(HaveOccurred())
			Expect(cs.secureAEAD).ToNot(BeNil())
			Expect(keyDerivationCalledWith.forwardSecure).To(BeFalse())
			Expect(keyDerivationCalledWith.sharedSecret).To(Equal(cs.serverConfig.sharedSecret))
			Expect(keyDerivationCalledWith.nonces).To(Equal(cs.nonc))
			Expect(keyDerivationCalledWith.connID).To(Equal(cs.connID))
			Expect(keyDerivationCalledWith.chlo).To(Equal(cs.lastSentCHLO))
			Expect(keyDerivationCalledWith.scfg).To(Equal(cs.serverConfig.Get()))
			Expect(keyDerivationCalledWith.cert).To(Equal(certManager.leafCert))
			Expect(keyDerivationCalledWith.divNonce).To(Equal(cs.diversificationNonce))
			Expect(keyDerivationCalledWith.pers).To(Equal(protocol.PerspectiveClient))
			Expect(cs.HandshakeComplete()).To(BeFalse())
			Expect(cs.aeadChanged).To(Receive())
		})

		It("uses the server nonce, if the server sent one", func() {
			cs.serverVerified = true
			cs.sno = []byte("server nonce")
			err := cs.maybeUpgradeCrypto()
			Expect(err).ToNot(HaveOccurred())
			Expect(cs.secureAEAD).ToNot(BeNil())
			Expect(keyDerivationCalledWith.nonces).To(Equal(append(cs.nonc, cs.sno...)))
			Expect(cs.HandshakeComplete()).To(BeFalse())
			Expect(cs.aeadChanged).To(Receive())
		})

		It("doesn't create a secureAEAD if the certificate is not yet verified, even if it has all necessary values", func() {
			err := cs.maybeUpgradeCrypto()
			Expect(err).ToNot(HaveOccurred())
			Expect(cs.secureAEAD).To(BeNil())
			Expect(cs.aeadChanged).ToNot(Receive())
			cs.serverVerified = true
			// make sure we really had all necessary values before, and only serverVerified was missing
			err = cs.maybeUpgradeCrypto()
			Expect(err).ToNot(HaveOccurred())
			Expect(cs.secureAEAD).ToNot(BeNil())
			Expect(cs.HandshakeComplete()).To(BeFalse())
			Expect(cs.aeadChanged).To(Receive())
		})

		It("tries to escalate before reading a handshake message", func() {
			Expect(cs.secureAEAD).To(BeNil())
			cs.serverVerified = true
			err := cs.HandleCryptoStream()
			// this will throw a qerr.HandshakeFailed due to an EOF in WriteHandshakeMessage
			// this is because the mockStream doesn't block if there's no data to read
			Expect(err).To(MatchError(qerr.HandshakeFailed))
			Expect(cs.secureAEAD).ToNot(BeNil())
			Expect(cs.HandshakeComplete()).To(BeFalse())
		})

		It("tries to escalate the crypto after receiving a diversification nonce", func() {
			cs.diversificationNonce = nil
			cs.serverVerified = true
			Expect(cs.secureAEAD).To(BeNil())
			err := cs.SetDiversificationNonce([]byte("div"))
			Expect(err).ToNot(HaveOccurred())
			Expect(cs.secureAEAD).ToNot(BeNil())
			Expect(cs.aeadChanged).To(Receive())
			Expect(cs.HandshakeComplete()).To(BeFalse())
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
