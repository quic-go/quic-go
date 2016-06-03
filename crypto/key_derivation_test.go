package crypto

import (
	"github.com/lucas-clemente/quic-go/protocol"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("KeyDerivation", func() {
	It("derives non-fs keys", func() {
		aead, err := DeriveKeysChacha20(
			protocol.Version32,
			false,
			[]byte("0123456789012345678901"),
			[]byte("nonce"),
			protocol.ConnectionID(42),
			[]byte("chlo"),
			[]byte("scfg"),
			[]byte("cert"),
			nil,
		)
		Expect(err).ToNot(HaveOccurred())
		chacha := aead.(*aeadChacha20Poly1305)
		// If the IVs match, the keys will match too, since the keys are read earlier
		Expect(chacha.myIV).To(Equal([]byte{0xf0, 0xf5, 0x4c, 0xa8}))
		Expect(chacha.otherIV).To(Equal([]byte{0x75, 0xd8, 0xa2, 0x8d}))
	})

	It("derives fs keys", func() {
		aead, err := DeriveKeysChacha20(
			protocol.Version32,
			true,
			[]byte("0123456789012345678901"),
			[]byte("nonce"),
			protocol.ConnectionID(42),
			[]byte("chlo"),
			[]byte("scfg"),
			[]byte("cert"),
			nil,
		)
		Expect(err).ToNot(HaveOccurred())
		chacha := aead.(*aeadChacha20Poly1305)
		// If the IVs match, the keys will match too, since the keys are read earlier
		Expect(chacha.myIV).To(Equal([]byte{0xf5, 0x73, 0x11, 0x79}))
		Expect(chacha.otherIV).To(Equal([]byte{0xf7, 0x26, 0x4d, 0x2c}))
	})

	It("does not use diversification nonces in FS key derivation", func() {
		aead, err := DeriveKeysChacha20(
			protocol.Version33,
			true,
			[]byte("0123456789012345678901"),
			[]byte("nonce"),
			protocol.ConnectionID(42),
			[]byte("chlo"),
			[]byte("scfg"),
			[]byte("cert"),
			[]byte("divnonce"),
		)
		Expect(err).ToNot(HaveOccurred())
		chacha := aead.(*aeadChacha20Poly1305)
		// If the IVs match, the keys will match too, since the keys are read earlier
		Expect(chacha.myIV).To(Equal([]byte{0xf5, 0x73, 0x11, 0x79}))
		Expect(chacha.otherIV).To(Equal([]byte{0xf7, 0x26, 0x4d, 0x2c}))
	})

	It("uses diversification nonces in initial key derivation", func() {
		aead, err := DeriveKeysChacha20(
			protocol.Version33,
			false,
			[]byte("0123456789012345678901"),
			[]byte("nonce"),
			protocol.ConnectionID(42),
			[]byte("chlo"),
			[]byte("scfg"),
			[]byte("cert"),
			[]byte("divnonce"),
		)
		Expect(err).ToNot(HaveOccurred())
		chacha := aead.(*aeadChacha20Poly1305)
		// If the IVs match, the keys will match too, since the keys are read earlier
		Expect(chacha.myIV).To(Equal([]byte{0xc4, 0x12, 0x25, 0x64}))
		Expect(chacha.otherIV).To(Equal([]byte{0x75, 0xd8, 0xa2, 0x8d}))
	})
})
