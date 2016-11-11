package handshake

import (
	"bytes"
	"encoding/binary"
	"time"

	"github.com/lucas-clemente/quic-go/protocol"
	"github.com/lucas-clemente/quic-go/qerr"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Crypto setup", func() {
	var cs *cryptoSetupClient
	var stream *mockStream

	BeforeEach(func() {
		stream = &mockStream{}
		csInt, err := NewCryptoSetupClient(0, protocol.Version36, stream)
		Expect(err).ToNot(HaveOccurred())
		cs = csInt.(*cryptoSetupClient)
	})

	Context("Reading SHLOs", func() {
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
			tagMap[TagCERT] = []byte("invalid-cert")
			err := cs.handleREJMessage(tagMap)
			Expect(err).To(MatchError(qerr.ProofInvalid))
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

	Context("CHLO generation", func() {
		It("is longer than the miminum client hello size", func() {
			err := cs.sendCHLO()
			Expect(err).ToNot(HaveOccurred())
			Expect(cs.cryptoStream.(*mockStream).dataWritten.Len()).To(BeNumerically(">", protocol.ClientHelloMinimumSize))
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
