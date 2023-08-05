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
		cs  *MockCryptoDataHandler

		initialStream   *MockCryptoStream
		handshakeStream *MockCryptoStream
		oneRTTStream    *MockCryptoStream
	)

	BeforeEach(func() {
		initialStream = NewMockCryptoStream(mockCtrl)
		handshakeStream = NewMockCryptoStream(mockCtrl)
		oneRTTStream = NewMockCryptoStream(mockCtrl)
		cs = NewMockCryptoDataHandler(mockCtrl)
		csm = newCryptoStreamManager(cs, initialStream, handshakeStream, oneRTTStream)
	})

	It("passes messages to the initial stream", func() {
		cf := &wire.CryptoFrame{Data: []byte("foobar")}
		initialStream.EXPECT().HandleCryptoFrame(cf)
		initialStream.EXPECT().GetCryptoData().Return([]byte("foobar"))
		initialStream.EXPECT().GetCryptoData()
		cs.EXPECT().HandleMessage([]byte("foobar"), protocol.EncryptionInitial)
		Expect(csm.HandleCryptoFrame(cf, protocol.EncryptionInitial)).To(Succeed())
	})

	It("passes messages to the handshake stream", func() {
		cf := &wire.CryptoFrame{Data: []byte("foobar")}
		handshakeStream.EXPECT().HandleCryptoFrame(cf)
		handshakeStream.EXPECT().GetCryptoData().Return([]byte("foobar"))
		handshakeStream.EXPECT().GetCryptoData()
		cs.EXPECT().HandleMessage([]byte("foobar"), protocol.EncryptionHandshake)
		Expect(csm.HandleCryptoFrame(cf, protocol.EncryptionHandshake)).To(Succeed())
	})

	It("passes messages to the 1-RTT stream", func() {
		cf := &wire.CryptoFrame{Data: []byte("foobar")}
		oneRTTStream.EXPECT().HandleCryptoFrame(cf)
		oneRTTStream.EXPECT().GetCryptoData().Return([]byte("foobar"))
		oneRTTStream.EXPECT().GetCryptoData()
		cs.EXPECT().HandleMessage([]byte("foobar"), protocol.Encryption1RTT)
		Expect(csm.HandleCryptoFrame(cf, protocol.Encryption1RTT)).To(Succeed())
	})

	It("doesn't call the message handler, if there's no message", func() {
		cf := &wire.CryptoFrame{Data: []byte("foobar")}
		handshakeStream.EXPECT().HandleCryptoFrame(cf)
		handshakeStream.EXPECT().GetCryptoData() // don't return any data to handle
		// don't EXPECT any calls to HandleMessage()
		Expect(csm.HandleCryptoFrame(cf, protocol.EncryptionHandshake)).To(Succeed())
	})

	It("processes all messages", func() {
		cf := &wire.CryptoFrame{Data: []byte("foobar")}
		handshakeStream.EXPECT().HandleCryptoFrame(cf)
		handshakeStream.EXPECT().GetCryptoData().Return([]byte("foo"))
		handshakeStream.EXPECT().GetCryptoData().Return([]byte("bar"))
		handshakeStream.EXPECT().GetCryptoData()
		cs.EXPECT().HandleMessage([]byte("foo"), protocol.EncryptionHandshake)
		cs.EXPECT().HandleMessage([]byte("bar"), protocol.EncryptionHandshake)
		Expect(csm.HandleCryptoFrame(cf, protocol.EncryptionHandshake)).To(Succeed())
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
