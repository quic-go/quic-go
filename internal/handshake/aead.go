package handshake

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"fmt"

	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/marten-seemann/qtls"
)

type sealer struct {
	aead        cipher.AEAD
	hpEncrypter cipher.Block

	// use a single slice to avoid allocations
	nonceBuf []byte
	hpMask   []byte
}

var _ LongHeaderSealer = &sealer{}

func newLongHeaderSealer(aead cipher.AEAD, hpEncrypter cipher.Block) LongHeaderSealer {
	return &sealer{
		aead:        aead,
		nonceBuf:    make([]byte, aead.NonceSize()),
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
	*firstByte ^= s.hpMask[0] & 0xf
	for i := range pnBytes {
		pnBytes[i] ^= s.hpMask[i+1]
	}
}

func (s *sealer) Overhead() int {
	return s.aead.Overhead()
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
	dec, err := o.aead.Open(dst, o.nonceBuf, src, ad)
	if err != nil {
		err = ErrDecryptionFailed
	}
	return dec, err
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

func createAEAD(suite cipherSuite, trafficSecret []byte) cipher.AEAD {
	key := qtls.HkdfExpandLabel(suite.Hash(), trafficSecret, []byte{}, "quic key", suite.KeyLen())
	iv := qtls.HkdfExpandLabel(suite.Hash(), trafficSecret, []byte{}, "quic iv", suite.IVLen())
	return suite.AEAD(key, iv)
}

func createHeaderProtector(suite cipherSuite, trafficSecret []byte) cipher.Block {
	hpKey := qtls.HkdfExpandLabel(suite.Hash(), trafficSecret, []byte{}, "quic hp", suite.KeyLen())
	hp, err := aes.NewCipher(hpKey)
	if err != nil {
		panic(fmt.Sprintf("error creating new AES cipher: %s", err))
	}
	return hp
}
