package handshake

import (
	"encoding/binary"
	"time"

	"github.com/lucas-clemente/quic-go/protocol"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Crypto setup", func() {
	var cs cryptoSetupClient

	BeforeEach(func() {
		scfg := serverConfigClient{}
		cs = cryptoSetupClient{
			cryptoStream: &mockStream{},
			serverConfig: &scfg,
			version:      protocol.Version36,
		}
	})

	Context("Inchoate CHLO", func() {
		It("has the right values", func() {
			tags := cs.getInchoateCHLOValues()
			Expect(tags).To(HaveKey(TagSNI))
			Expect(tags[TagPDMD]).To(Equal([]byte("X509")))
			Expect(tags[TagVER]).To(Equal([]byte("Q036")))
		})

		It("is longer than the miminum client hello size", func() {
			err := cs.sendInchoateCHLO()
			Expect(err).ToNot(HaveOccurred())
			Expect(cs.cryptoStream.(*mockStream).dataWritten.Len()).To(BeNumerically(">", protocol.ClientHelloMinimumSize))
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
			cs.serverConfig.obit = []byte{0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8}
		})

		It("generates a client nonce", func() {
			now := time.Now()
			nonce, err := cs.generateClientNonce()
			Expect(nonce).To(HaveLen(32))
			Expect(err).ToNot(HaveOccurred())
			Expect(time.Unix(int64(binary.BigEndian.Uint32(nonce[0:4])), 0)).To(BeTemporally("~", now, 1*time.Second))
			Expect(nonce[4:12]).To(Equal(cs.serverConfig.obit))
		})

		It("uses random values for the last 20 bytes", func() {
			nonce1, err := cs.generateClientNonce()
			Expect(err).ToNot(HaveOccurred())
			nonce2, err := cs.generateClientNonce()
			Expect(err).ToNot(HaveOccurred())
			Expect(nonce1[4:12]).To(Equal(nonce2[4:12]))
			Expect(nonce1[12:]).ToNot(Equal(nonce2[12:]))
		})

		It("errors if no OBIT value is available", func() {
			cs.serverConfig.obit = []byte{}
			_, err := cs.generateClientNonce()
			Expect(err).To(MatchError(errNoObitForClientNonce))
		})
	})
})
