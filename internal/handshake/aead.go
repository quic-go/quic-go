package handshake

import (
	"crypto/cipher"
	"encoding/binary"

	"github.com/lucas-clemente/quic-go/internal/protocol"
)

type sealer struct {
	aead        cipher.AEAD
	hpEncrypter cipher.Block

	// use a single slice to avoid allocations
	nonceBuf []byte
	hpMask   []byte

	// short headers protect 5 bits in the first byte, long headers only 4
	is1RTT bool
}

var _ LongHeaderSealer = &sealer{}
var _ ShortHeaderSealer = &sealer{}

func newSealer(aead cipher.AEAD, hpEncrypter cipher.Block, is1RTT bool) ShortHeaderSealer {
	return &sealer{
		aead:        aead,
		nonceBuf:    make([]byte, aead.NonceSize()),
		is1RTT:      is1RTT,
		hpEncrypter: hpEncrypter,
		hpMask:      make([]byte, hpEncrypter.BlockSize()),
	}
}

func (s *sealer) Seal(dst, src []byte, pn protocol.PacketNumber, ad []byte) []byte {
	binary.BigEndian.PutUint64(s.nonceBuf[len(s.nonceBuf)-8:], uint64(pn))
	// The AEAD we're using here will be the qtls.aeadAESGCM13.
	// It uses the nonce provided here and XOR it with the IV.
	return s.aead.Seal(dst, s.nonceBuf, src, ad)
}

func (s *sealer) EncryptHeader(sample []byte, firstByte *byte, pnBytes []byte) {
	if len(sample) != s.hpEncrypter.BlockSize() {
		panic("invalid sample size")
	}
	s.hpEncrypter.Encrypt(s.hpMask, sample)
	if s.is1RTT {
		*firstByte ^= s.hpMask[0] & 0x1f
	} else {
		*firstByte ^= s.hpMask[0] & 0xf
	}
	for i := range pnBytes {
		pnBytes[i] ^= s.hpMask[i+1]
	}
}

func (s *sealer) Overhead() int {
	return s.aead.Overhead()
}

func (s *sealer) KeyPhase() protocol.KeyPhase {
	return protocol.KeyPhaseZero
}

type longHeaderOpener struct {
	aead        cipher.AEAD
	pnDecrypter cipher.Block

	// use a single slice to avoid allocations
	nonceBuf []byte
	hpMask   []byte
}

var _ LongHeaderOpener = &longHeaderOpener{}

func newLongHeaderOpener(aead cipher.AEAD, pnDecrypter cipher.Block) LongHeaderOpener {
	return &longHeaderOpener{
		aead:        aead,
		nonceBuf:    make([]byte, aead.NonceSize()),
		pnDecrypter: pnDecrypter,
		hpMask:      make([]byte, pnDecrypter.BlockSize()),
	}
}

func (o *longHeaderOpener) Open(dst, src []byte, pn protocol.PacketNumber, ad []byte) ([]byte, error) {
	binary.BigEndian.PutUint64(o.nonceBuf[len(o.nonceBuf)-8:], uint64(pn))
	// The AEAD we're using here will be the qtls.aeadAESGCM13.
	// It uses the nonce provided here and XOR it with the IV.
	return o.aead.Open(dst, o.nonceBuf, src, ad)
}

func (o *longHeaderOpener) DecryptHeader(sample []byte, firstByte *byte, pnBytes []byte) {
	if len(sample) != o.pnDecrypter.BlockSize() {
		panic("invalid sample size")
	}
	o.pnDecrypter.Encrypt(o.hpMask, sample)
	*firstByte ^= o.hpMask[0] & 0xf
	for i := range pnBytes {
		pnBytes[i] ^= o.hpMask[i+1]
	}
}

type shortHeaderOpener struct {
	aead        cipher.AEAD
	pnDecrypter cipher.Block

	// use a single slice to avoid allocations
	nonceBuf []byte
	hpMask   []byte
}

var _ ShortHeaderOpener = &shortHeaderOpener{}

func newShortHeaderOpener(aead cipher.AEAD, pnDecrypter cipher.Block) ShortHeaderOpener {
	return &shortHeaderOpener{
		aead:        aead,
		nonceBuf:    make([]byte, aead.NonceSize()),
		pnDecrypter: pnDecrypter,
		hpMask:      make([]byte, pnDecrypter.BlockSize()),
	}
}

func (o *shortHeaderOpener) Open(dst, src []byte, pn protocol.PacketNumber, _ protocol.KeyPhase, ad []byte) ([]byte, error) {
	binary.BigEndian.PutUint64(o.nonceBuf[len(o.nonceBuf)-8:], uint64(pn))
	// The AEAD we're using here will be the qtls.aeadAESGCM13.
	// It uses the nonce provided here and XOR it with the IV.
	return o.aead.Open(dst, o.nonceBuf, src, ad)
}

func (o *shortHeaderOpener) DecryptHeader(sample []byte, firstByte *byte, pnBytes []byte) {
	if len(sample) != o.pnDecrypter.BlockSize() {
		panic("invalid sample size")
	}
	o.pnDecrypter.Encrypt(o.hpMask, sample)
	*firstByte ^= o.hpMask[0] & 0x1f
	for i := range pnBytes {
		pnBytes[i] ^= o.hpMask[i+1]
	}
}
