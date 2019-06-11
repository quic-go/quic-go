package handshake

import (
	"crypto/cipher"
	"encoding/binary"

	"github.com/lucas-clemente/quic-go/internal/protocol"
)

type shortHeaderOpener struct {
	aead cipher.AEAD

	// use a single slice to avoid allocations
	nonceBuf []byte
}

func newShortHeaderOpener(aead cipher.AEAD) *shortHeaderOpener {
	return &shortHeaderOpener{
		aead:     aead,
		nonceBuf: make([]byte, aead.NonceSize()),
	}
}

func (o *shortHeaderOpener) Open(dst, src []byte, pn protocol.PacketNumber, _ protocol.KeyPhase, ad []byte) ([]byte, error) {
	binary.BigEndian.PutUint64(o.nonceBuf[len(o.nonceBuf)-8:], uint64(pn))
	// The AEAD we're using here will be the qtls.aeadAESGCM13.
	// It uses the nonce provided here and XOR it with the IV.
	return o.aead.Open(dst, o.nonceBuf, src, ad)
}

type shortHeaderSealer struct {
	sealer
}

func newShortHeaderSealer(aead cipher.AEAD) *shortHeaderSealer {
	return &shortHeaderSealer{
		sealer: sealer{
			aead:     aead,
			nonceBuf: make([]byte, aead.NonceSize()),
		},
	}
}

func (s *shortHeaderSealer) KeyPhase() protocol.KeyPhase {
	return protocol.KeyPhaseOne
}

type updatableAEAD struct {
	*shortHeaderSealer
	*shortHeaderOpener

	hpDecrypter cipher.Block
	hpEncrypter cipher.Block

	// use a single slice to avoid allocations
	hpMask []byte
}

var _ ShortHeaderOpener = &updatableAEAD{}
var _ ShortHeaderSealer = &updatableAEAD{}

func newUpdatableAEAD() *updatableAEAD {
	return &updatableAEAD{}
}

func (a *updatableAEAD) SetReadKey(suite cipherSuite, trafficSecret []byte) {
	aead, hpDecrypter := createAEAD(suite, trafficSecret)
	a.shortHeaderOpener = newShortHeaderOpener(aead)
	if len(a.hpMask) == 0 {
		a.hpMask = make([]byte, hpDecrypter.BlockSize())
	} else if len(a.hpMask) != hpDecrypter.BlockSize() {
		panic("invalid header protection block size")
	}
	a.hpDecrypter = hpDecrypter
}

func (a *updatableAEAD) SetWriteKey(suite cipherSuite, trafficSecret []byte) {
	aead, hpEncrypter := createAEAD(suite, trafficSecret)
	a.shortHeaderSealer = newShortHeaderSealer(aead)
	if len(a.hpMask) == 0 {
		a.hpMask = make([]byte, hpEncrypter.BlockSize())
	} else if len(a.hpMask) != hpEncrypter.BlockSize() {
		panic("invalid header protection block size")
	}
	a.hpEncrypter = hpEncrypter
}

func (a *updatableAEAD) EncryptHeader(sample []byte, firstByte *byte, pnBytes []byte) {
	if len(sample) != a.hpEncrypter.BlockSize() {
		panic("invalid sample size")
	}
	a.hpEncrypter.Encrypt(a.hpMask, sample)
	*firstByte ^= a.hpMask[0] & 0x1f
	for i := range pnBytes {
		pnBytes[i] ^= a.hpMask[i+1]
	}
}

func (a *updatableAEAD) DecryptHeader(sample []byte, firstByte *byte, pnBytes []byte) {
	if len(sample) != a.hpDecrypter.BlockSize() {
		panic("invalid sample size")
	}
	a.hpDecrypter.Encrypt(a.hpMask, sample)
	*firstByte ^= a.hpMask[0] & 0x1f
	for i := range pnBytes {
		pnBytes[i] ^= a.hpMask[i+1]
	}
}
