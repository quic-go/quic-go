package quic

import (
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/wire"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Crypto Stream Manager", func() {
	var (
		csm *cryptoStreamManager

		initialStream   *cryptoStream
		handshakeStream *cryptoStream
		oneRTTStream    *cryptoStream
	)

	BeforeEach(func() {
		initialStream = newCryptoStream()
		handshakeStream = newCryptoStream()
		oneRTTStream = newCryptoStream()
		csm = newCryptoStreamManager(initialStream, handshakeStream, oneRTTStream)
	})

	It("passes messages to the initial stream", func() {
		cf := &wire.CryptoFrame{Data: []byte("foobar")}
		Expect(csm.HandleCryptoFrame(cf, protocol.EncryptionInitial)).To(Succeed())
		Expect(csm.GetCryptoData(protocol.EncryptionInitial)).To(Equal([]byte("foobar")))
	})

	It("passes messages to the handshake stream", func() {
		cf := &wire.CryptoFrame{Data: []byte("foobar")}
		Expect(csm.HandleCryptoFrame(cf, protocol.EncryptionHandshake)).To(Succeed())
		Expect(csm.GetCryptoData(protocol.EncryptionHandshake)).To(Equal([]byte("foobar")))
	})

	It("passes messages to the 1-RTT stream", func() {
		cf := &wire.CryptoFrame{Data: []byte("foobar")}
		Expect(csm.HandleCryptoFrame(cf, protocol.Encryption1RTT)).To(Succeed())
		Expect(csm.GetCryptoData(protocol.Encryption1RTT)).To(Equal([]byte("foobar")))
	})

	It("processes all messages", func() {
		Expect(csm.HandleCryptoFrame(&wire.CryptoFrame{Data: []byte("bar"), Offset: 3}, protocol.EncryptionHandshake)).To(Succeed())
		Expect(csm.HandleCryptoFrame(&wire.CryptoFrame{Data: []byte("foo")}, protocol.EncryptionHandshake)).To(Succeed())
		var data []byte
		for {
			b := csm.GetCryptoData(protocol.EncryptionHandshake)
			if len(b) == 0 {
				break
			}
			data = append(data, b...)
		}
		Expect(data).To(Equal([]byte("foobar")))
	})

	It("errors for unknown encryption levels", func() {
		err := csm.HandleCryptoFrame(&wire.CryptoFrame{}, 42)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("received CRYPTO frame with unexpected encryption level"))
	})

	It("drops Initial", func() {
		Expect(initialStream.HandleCryptoFrame(&wire.CryptoFrame{Data: []byte("foo")})).To(Succeed())
		err := csm.Drop(protocol.EncryptionInitial)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("encryption level changed, but crypto stream has more data to read"))
	})

	It("drops Handshake", func() {
		Expect(handshakeStream.HandleCryptoFrame(&wire.CryptoFrame{Data: []byte("foo")})).To(Succeed())
		err := csm.Drop(protocol.EncryptionHandshake)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("encryption level changed, but crypto stream has more data to read"))
	})
})
