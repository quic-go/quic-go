package handshake

import (
	"crypto/cipher"
	"encoding/binary"

	"github.com/lucas-clemente/quic-go/internal/protocol"
)

type updatableAEAD struct {
	openAEAD cipher.AEAD
	sealAEAD cipher.AEAD

	hpDecrypter cipher.Block
	hpEncrypter cipher.Block

	// use a single slice to avoid allocations
	nonceBuf []byte
	hpMask   []byte
}

var _ ShortHeaderOpener = &updatableAEAD{}
var _ ShortHeaderSealer = &updatableAEAD{}

func newUpdatableAEAD() *updatableAEAD {
	return &updatableAEAD{}
}

func (a *updatableAEAD) SetReadKey(suite cipherSuite, trafficSecret []byte) {
	aead, hpDecrypter := createAEAD(suite, trafficSecret)
	if len(a.nonceBuf) == 0 {
		a.nonceBuf = make([]byte, aead.NonceSize())
	} else if len(a.nonceBuf) != aead.NonceSize() {
		panic("invalid nonce size")
	}
	a.openAEAD = aead

	if len(a.hpMask) == 0 {
		a.hpMask = make([]byte, hpDecrypter.BlockSize())
	} else if len(a.hpMask) != hpDecrypter.BlockSize() {
		panic("invalid header protection block size")
	}
	a.hpDecrypter = hpDecrypter
}

func (a *updatableAEAD) SetWriteKey(suite cipherSuite, trafficSecret []byte) {
	aead, hpEncrypter := createAEAD(suite, trafficSecret)
	if len(a.nonceBuf) == 0 {
		a.nonceBuf = make([]byte, aead.NonceSize())
	} else if len(a.nonceBuf) != aead.NonceSize() {
		panic("invalid nonce size")
	}
	a.sealAEAD = aead

	if len(a.hpMask) == 0 {
		a.hpMask = make([]byte, hpEncrypter.BlockSize())
	} else if len(a.hpMask) != hpEncrypter.BlockSize() {
		panic("invalid header protection block size")
	}
	a.hpEncrypter = hpEncrypter
}

func (a *updatableAEAD) Open(dst, src []byte, pn protocol.PacketNumber, _ protocol.KeyPhase, ad []byte) ([]byte, error) {
	binary.BigEndian.PutUint64(a.nonceBuf[len(a.nonceBuf)-8:], uint64(pn))
	// The AEAD we're using here will be the qtls.aeadAESGCM13.
	// It uses the nonce provided here and XOR it with the IV.
	return a.openAEAD.Open(dst, a.nonceBuf, src, ad)
}

func (a *updatableAEAD) Seal(dst, src []byte, pn protocol.PacketNumber, ad []byte) []byte {
	binary.BigEndian.PutUint64(a.nonceBuf[len(a.nonceBuf)-8:], uint64(pn))
	// The AEAD we're using here will be the qtls.aeadAESGCM13.
	// It uses the nonce provided here and XOR it with the IV.
	return a.sealAEAD.Seal(dst, a.nonceBuf, src, ad)
}

func (a *updatableAEAD) KeyPhase() protocol.KeyPhase {
	return protocol.KeyPhaseOne
}

func (a *updatableAEAD) Overhead() int {
	return a.sealAEAD.Overhead()
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
