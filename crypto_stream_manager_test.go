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

		initialStream   *MockCryptoStream
		handshakeStream *MockCryptoStream
		oneRTTStream    *MockCryptoStream
	)

	BeforeEach(func() {
		initialStream = NewMockCryptoStream(mockCtrl)
		handshakeStream = NewMockCryptoStream(mockCtrl)
		oneRTTStream = NewMockCryptoStream(mockCtrl)
		csm = newCryptoStreamManager(initialStream, handshakeStream, oneRTTStream)
	})

	It("passes messages to the initial stream", func() {
		cf := &wire.CryptoFrame{Data: []byte("foobar")}
		initialStream.EXPECT().HandleCryptoFrame(cf)
		initialStream.EXPECT().GetCryptoData().Return([]byte("foobar"))
		Expect(csm.HandleCryptoFrame(cf, protocol.EncryptionInitial)).To(Succeed())
		Expect(csm.GetCryptoData(protocol.EncryptionInitial)).To(Equal([]byte("foobar")))
	})

	It("passes messages to the handshake stream", func() {
		cf := &wire.CryptoFrame{Data: []byte("foobar")}
		handshakeStream.EXPECT().HandleCryptoFrame(cf)
		handshakeStream.EXPECT().GetCryptoData().Return([]byte("foobar"))
		Expect(csm.HandleCryptoFrame(cf, protocol.EncryptionHandshake)).To(Succeed())
		Expect(csm.GetCryptoData(protocol.EncryptionHandshake)).To(Equal([]byte("foobar")))
	})

	It("passes messages to the 1-RTT stream", func() {
		cf := &wire.CryptoFrame{Data: []byte("foobar")}
		oneRTTStream.EXPECT().HandleCryptoFrame(cf)
		oneRTTStream.EXPECT().GetCryptoData().Return([]byte("foobar"))
		Expect(csm.HandleCryptoFrame(cf, protocol.Encryption1RTT)).To(Succeed())
		Expect(csm.GetCryptoData(protocol.Encryption1RTT)).To(Equal([]byte("foobar")))
	})

	It("processes all messages", func() {
		cf := &wire.CryptoFrame{Data: []byte("foobar")}
		handshakeStream.EXPECT().HandleCryptoFrame(cf)
		handshakeStream.EXPECT().GetCryptoData().Return([]byte("foo"))
		handshakeStream.EXPECT().GetCryptoData().Return([]byte("bar"))
		handshakeStream.EXPECT().GetCryptoData()
		Expect(csm.HandleCryptoFrame(cf, protocol.EncryptionHandshake)).To(Succeed())
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
		initialStream.EXPECT().Finish()
		Expect(csm.Drop(protocol.EncryptionInitial)).To(Succeed())
	})

	It("drops Handshake", func() {
		handshakeStream.EXPECT().Finish()
		Expect(csm.Drop(protocol.EncryptionHandshake)).To(Succeed())
	})
})
