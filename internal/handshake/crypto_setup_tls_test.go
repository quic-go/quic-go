package handshake

import (
	"errors"
	"fmt"

	"github.com/bifurcation/mint"
	"github.com/lucas-clemente/quic-go/internal/crypto"
	"github.com/lucas-clemente/quic-go/internal/mocks/crypto"
	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/testdata"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

type fakeMintTLS struct {
	result mint.Alert
}

var _ mintTLS = &fakeMintTLS{}

func (h *fakeMintTLS) Handshake() mint.Alert {
	return h.result
}
func (h *fakeMintTLS) GetCipherSuite() mint.CipherSuiteParams { panic("not implemented") }
func (h *fakeMintTLS) ComputeExporter(label string, context []byte, keyLength int) ([]byte, error) {
	panic("not implemented")
}
func (h *fakeMintTLS) SetExtensionHandler(mint.AppExtensionHandler) error {
	panic("not implemented")
}

func mockKeyDerivation(crypto.TLSExporter, protocol.Perspective) (crypto.AEAD, error) {
	return mockcrypto.NewMockAEAD(mockCtrl), nil
}

var _ = Describe("TLS Crypto Setup", func() {
	var (
		cs          *cryptoSetupTLS
		paramsChan  chan TransportParameters
		aeadChanged chan protocol.EncryptionLevel
	)

	BeforeEach(func() {
		paramsChan = make(chan TransportParameters)
		aeadChanged = make(chan protocol.EncryptionLevel, 2)
		csInt, err := NewCryptoSetupTLSServer(
			nil,
			1,
			testdata.GetTLSConfig(),
			&TransportParameters{},
			paramsChan,
			aeadChanged,
			nil,
			protocol.VersionTLS,
		)
		Expect(err).ToNot(HaveOccurred())
		cs = csInt.(*cryptoSetupTLS)
		cs.nullAEAD = mockcrypto.NewMockAEAD(mockCtrl)
	})

	It("errors when the handshake fails", func() {
		alert := mint.AlertBadRecordMAC
		cs.tls = &fakeMintTLS{result: alert}
		err := cs.HandleCryptoStream()
		Expect(err).To(MatchError(fmt.Errorf("TLS handshake error: %s (Alert %d)", alert.String(), alert)))
	})

	It("derives keys", func() {
		cs.tls = &fakeMintTLS{result: mint.AlertNoAlert}
		cs.keyDerivation = mockKeyDerivation
		err := cs.HandleCryptoStream()
		Expect(err).ToNot(HaveOccurred())
		Expect(aeadChanged).To(Receive(Equal(protocol.EncryptionForwardSecure)))
		Expect(aeadChanged).To(BeClosed())
	})

	Context("escalating crypto", func() {
		doHandshake := func() {
			cs.tls = &fakeMintTLS{result: mint.AlertNoAlert}
			cs.keyDerivation = mockKeyDerivation
			err := cs.HandleCryptoStream()
			Expect(err).ToNot(HaveOccurred())
		}

		Context("null encryption", func() {
			It("is used initially", func() {
				cs.nullAEAD.(*mockcrypto.MockAEAD).EXPECT().Seal(nil, []byte("foobar"), protocol.PacketNumber(5), []byte{}).Return([]byte("foobar signed"))
				enc, sealer := cs.GetSealer()
				Expect(enc).To(Equal(protocol.EncryptionUnencrypted))
				d := sealer.Seal(nil, []byte("foobar"), 5, []byte{})
				Expect(d).To(Equal([]byte("foobar signed")))
			})

			It("is accepted initially", func() {
				cs.nullAEAD.(*mockcrypto.MockAEAD).EXPECT().Open(nil, []byte("foobar enc"), protocol.PacketNumber(10), []byte{}).Return([]byte("foobar"), nil)
				d, enc, err := cs.Open(nil, []byte("foobar enc"), 10, []byte{})
				Expect(err).ToNot(HaveOccurred())
				Expect(d).To(Equal([]byte("foobar")))
				Expect(enc).To(Equal(protocol.EncryptionUnencrypted))
			})

			It("is used for crypto stream", func() {
				cs.nullAEAD.(*mockcrypto.MockAEAD).EXPECT().Seal(nil, []byte("foobar"), protocol.PacketNumber(20), []byte{}).Return([]byte("foobar signed"))
				enc, sealer := cs.GetSealerForCryptoStream()
				Expect(enc).To(Equal(protocol.EncryptionUnencrypted))
				d := sealer.Seal(nil, []byte("foobar"), 20, []byte{})
				Expect(d).To(Equal([]byte("foobar signed")))
			})

			It("errors if the has the wrong hash", func() {
				cs.nullAEAD.(*mockcrypto.MockAEAD).EXPECT().Open(nil, []byte("foobar enc"), protocol.PacketNumber(10), []byte{}).Return(nil, errors.New("authentication failed"))
				_, enc, err := cs.Open(nil, []byte("foobar enc"), 10, []byte{})
				Expect(err).To(MatchError("authentication failed"))
				Expect(enc).To(Equal(protocol.EncryptionUnspecified))
			})

			It("is not accepted after the handshake completes", func() {
				doHandshake()
				cs.aead.(*mockcrypto.MockAEAD).EXPECT().Open(nil, []byte("foobar encrypted"), protocol.PacketNumber(1), []byte{}).Return(nil, errors.New("authentication failed"))
				_, enc, err := cs.Open(nil, []byte("foobar encrypted"), 1, []byte{})
				Expect(err).To(MatchError("authentication failed"))
				Expect(enc).To(Equal(protocol.EncryptionUnspecified))
			})
		})

		Context("forward-secure encryption", func() {
			It("is used for sealing after the handshake completes", func() {
				doHandshake()
				cs.aead.(*mockcrypto.MockAEAD).EXPECT().Seal(nil, []byte("foobar"), protocol.PacketNumber(5), []byte{}).Return([]byte("foobar forward sec"))
				enc, sealer := cs.GetSealer()
				Expect(enc).To(Equal(protocol.EncryptionForwardSecure))
				d := sealer.Seal(nil, []byte("foobar"), 5, []byte{})
				Expect(d).To(Equal([]byte("foobar forward sec")))
			})

			It("is used for opening after the handshake completes", func() {
				doHandshake()
				cs.aead.(*mockcrypto.MockAEAD).EXPECT().Open(nil, []byte("encrypted"), protocol.PacketNumber(6), []byte{}).Return([]byte("decrypted"), nil)
				d, enc, err := cs.Open(nil, []byte("encrypted"), 6, []byte{})
				Expect(err).ToNot(HaveOccurred())
				Expect(enc).To(Equal(protocol.EncryptionForwardSecure))
				Expect(d).To(Equal([]byte("decrypted")))
			})
		})

		Context("forcing encryption levels", func() {
			It("forces null encryption", func() {
				doHandshake()
				cs.nullAEAD.(*mockcrypto.MockAEAD).EXPECT().Seal(nil, []byte("foobar"), protocol.PacketNumber(5), []byte{}).Return([]byte("foobar signed"))
				sealer, err := cs.GetSealerWithEncryptionLevel(protocol.EncryptionUnencrypted)
				Expect(err).ToNot(HaveOccurred())
				d := sealer.Seal(nil, []byte("foobar"), 5, []byte{})
				Expect(d).To(Equal([]byte("foobar signed")))
			})

			It("forces forward-secure encryption", func() {
				doHandshake()
				cs.aead.(*mockcrypto.MockAEAD).EXPECT().Seal(nil, []byte("foobar"), protocol.PacketNumber(5), []byte{}).Return([]byte("foobar forward sec"))
				sealer, err := cs.GetSealerWithEncryptionLevel(protocol.EncryptionForwardSecure)
				Expect(err).ToNot(HaveOccurred())
				d := sealer.Seal(nil, []byte("foobar"), 5, []byte{})
				Expect(d).To(Equal([]byte("foobar forward sec")))
			})

			It("errors if the forward-secure AEAD is not available", func() {
				sealer, err := cs.GetSealerWithEncryptionLevel(protocol.EncryptionForwardSecure)
				Expect(err).To(MatchError("CryptoSetup: no sealer with encryption level forward-secure"))
				Expect(sealer).To(BeNil())
			})

			It("never returns a secure AEAD (they don't exist with TLS)", func() {
				doHandshake()
				sealer, err := cs.GetSealerWithEncryptionLevel(protocol.EncryptionSecure)
				Expect(err).To(MatchError("CryptoSetup: no sealer with encryption level encrypted (not forward-secure)"))
				Expect(sealer).To(BeNil())
			})

			It("errors if no encryption level is specified", func() {
				seal, err := cs.GetSealerWithEncryptionLevel(protocol.EncryptionUnspecified)
				Expect(err).To(MatchError("CryptoSetup: no sealer with encryption level unknown"))
				Expect(seal).To(BeNil())
			})
		})
	})
})
