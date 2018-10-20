package quic

import (
	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/wire"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Crypto Stream Manager", func() {
	var (
		csm *cryptoStreamManager
		cs  *MockCryptoDataHandler
	)

	BeforeEach(func() {
		initialStream := newCryptoStream()
		handshakeStream := newCryptoStream()
		cs = NewMockCryptoDataHandler(mockCtrl)
		csm = newCryptoStreamManager(cs, initialStream, handshakeStream)
	})

	It("passes messages to the right stream", func() {
		initialMsg := createHandshakeMessage(10)
		handshakeMsg := createHandshakeMessage(20)

		// only pass in a part of the message, to make sure they get assembled in the right crypto stream
		Expect(csm.HandleCryptoFrame(&wire.CryptoFrame{
			Data: initialMsg[:5],
		}, protocol.EncryptionInitial)).To(Succeed())
		Expect(csm.HandleCryptoFrame(&wire.CryptoFrame{
			Data: handshakeMsg[:5],
		}, protocol.EncryptionHandshake)).To(Succeed())

		// now pass in the rest of the initial message
		cs.EXPECT().HandleMessage(initialMsg, protocol.EncryptionInitial)
		Expect(csm.HandleCryptoFrame(&wire.CryptoFrame{
			Data:   initialMsg[5:],
			Offset: 5,
		}, protocol.EncryptionInitial)).To(Succeed())

		// now pass in the rest of the handshake message
		cs.EXPECT().HandleMessage(handshakeMsg, protocol.EncryptionHandshake)
		Expect(csm.HandleCryptoFrame(&wire.CryptoFrame{
			Data:   handshakeMsg[5:],
			Offset: 5,
		}, protocol.EncryptionHandshake)).To(Succeed())
	})

	It("errors for unknown encryption levels", func() {
		err := csm.HandleCryptoFrame(&wire.CryptoFrame{}, protocol.Encryption1RTT)
		Expect(err).To(MatchError("received CRYPTO frame with unexpected encryption level: 1-RTT"))
	})
})
