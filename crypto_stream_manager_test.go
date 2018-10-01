package quic

import (
	"errors"

	"github.com/golang/mock/gomock"
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

	It("handles in in-order crypto frame", func() {
		f := &wire.CryptoFrame{Data: []byte("foobar")}
		cs.EXPECT().HandleData([]byte("foobar"), protocol.EncryptionInitial)
		Expect(csm.HandleCryptoFrame(f, protocol.EncryptionInitial)).To(Succeed())
	})

	It("errors for unknown encryption levels", func() {
		err := csm.HandleCryptoFrame(&wire.CryptoFrame{}, protocol.Encryption1RTT)
		Expect(err).To(MatchError("received CRYPTO frame with unexpected encryption level: 1-RTT"))
	})

	It("handles out-of-order crypto frames", func() {
		f1 := &wire.CryptoFrame{Data: []byte("foo")}
		f2 := &wire.CryptoFrame{
			Offset: 3,
			Data:   []byte("bar"),
		}
		gomock.InOrder(
			cs.EXPECT().HandleData([]byte("foo"), protocol.EncryptionInitial),
			cs.EXPECT().HandleData([]byte("bar"), protocol.EncryptionInitial),
		)
		Expect(csm.HandleCryptoFrame(f1, protocol.EncryptionInitial)).To(Succeed())
		Expect(csm.HandleCryptoFrame(f2, protocol.EncryptionInitial)).To(Succeed())
	})

	It("handles handshake data", func() {
		f := &wire.CryptoFrame{Data: []byte("foobar")}
		cs.EXPECT().HandleData([]byte("foobar"), protocol.EncryptionHandshake)
		Expect(csm.HandleCryptoFrame(f, protocol.EncryptionHandshake)).To(Succeed())
	})

	It("returns the error if handling crypto data fails", func() {
		testErr := errors.New("test error")
		f := &wire.CryptoFrame{Data: []byte("foobar")}
		cs.EXPECT().HandleData([]byte("foobar"), protocol.EncryptionHandshake).Return(testErr)
		err := csm.HandleCryptoFrame(f, protocol.EncryptionHandshake)
		Expect(err).To(MatchError(testErr))
	})
})
