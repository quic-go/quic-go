package handshake

import (
	"crypto/cipher"
	"encoding/binary"

	"github.com/lucas-clemente/quic-go/internal/protocol"
)

type shortHeaderOpener struct {
	aead        cipher.AEAD
	hpDecrypter cipher.Block

	// use a single slice to avoid allocations
	nonceBuf []byte
	hpMask   []byte
}

var _ ShortHeaderOpener = &shortHeaderOpener{}

func newShortHeaderOpener(aead cipher.AEAD, hpDecrypter cipher.Block) ShortHeaderOpener {
	return &shortHeaderOpener{
		aead:        aead,
		nonceBuf:    make([]byte, aead.NonceSize()),
		hpDecrypter: hpDecrypter,
		hpMask:      make([]byte, hpDecrypter.BlockSize()),
	}
}

func (o *shortHeaderOpener) Open(dst, src []byte, pn protocol.PacketNumber, _ protocol.KeyPhase, ad []byte) ([]byte, error) {
	binary.BigEndian.PutUint64(o.nonceBuf[len(o.nonceBuf)-8:], uint64(pn))
	// The AEAD we're using here will be the qtls.aeadAESGCM13.
	// It uses the nonce provided here and XOR it with the IV.
	return o.aead.Open(dst, o.nonceBuf, src, ad)
}

func (o *shortHeaderOpener) DecryptHeader(sample []byte, firstByte *byte, pnBytes []byte) {
	if len(sample) != o.hpDecrypter.BlockSize() {
		panic("invalid sample size")
	}
	o.hpDecrypter.Encrypt(o.hpMask, sample)
	*firstByte ^= o.hpMask[0] & 0x1f
	for i := range pnBytes {
		pnBytes[i] ^= o.hpMask[i+1]
	}
}

type shortHeaderSealer struct {
	sealer
}

func newShortHeaderSealer(aead cipher.AEAD, hpEncrypter cipher.Block) ShortHeaderSealer {
	return &shortHeaderSealer{
		sealer: sealer{
			aead:        aead,
			nonceBuf:    make([]byte, aead.NonceSize()),
			hpEncrypter: hpEncrypter,
			hpMask:      make([]byte, hpEncrypter.BlockSize()),
		},
	}
}

func (s *shortHeaderSealer) EncryptHeader(sample []byte, firstByte *byte, pnBytes []byte) {
	if len(sample) != s.hpEncrypter.BlockSize() {
		panic("invalid sample size")
	}
	s.hpEncrypter.Encrypt(s.hpMask, sample)
	*firstByte ^= s.hpMask[0] & 0x1f
	for i := range pnBytes {
		pnBytes[i] ^= s.hpMask[i+1]
	}
}

func (s *shortHeaderSealer) KeyPhase() protocol.KeyPhase {
	return protocol.KeyPhaseOne
}

type updatableAEAD struct {
	ShortHeaderOpener
	ShortHeaderSealer
}

func newUpdatableAEAD() *updatableAEAD {
	return &updatableAEAD{}
}

func (a *updatableAEAD) SetReadKey(aead cipher.AEAD, hpDecrypter cipher.Block) {
	a.ShortHeaderOpener = newShortHeaderOpener(aead, hpDecrypter)
}

func (a *updatableAEAD) SetWriteKey(aead cipher.AEAD, hpDecrypter cipher.Block) {
	a.ShortHeaderSealer = newShortHeaderSealer(aead, hpDecrypter)
}
