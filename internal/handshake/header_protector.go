package handshake

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"

	"github.com/marten-seemann/qtls"
)

type headerProtector interface {
	EncryptHeader(sample []byte, firstByte *byte, hdrBytes []byte)
	DecryptHeader(sample []byte, firstByte *byte, hdrBytes []byte)
}

func createAESHeaderProtector(suite cipherSuite, trafficSecret []byte) cipher.Block {
	hpKey := qtls.HkdfExpandLabel(suite.Hash(), trafficSecret, []byte{}, "quic hp", suite.KeyLen())
	hp, err := aes.NewCipher(hpKey)
	if err != nil {
		panic(fmt.Sprintf("error creating new AES cipher: %s", err))
	}
	return hp
}

type aesHeaderProtector struct {
	mask         []byte
	block        cipher.Block
	isLongHeader bool
}

var _ headerProtector = &aesHeaderProtector{}

func newAESHeaderProtector(block cipher.Block, isLongHeader bool) headerProtector {
	return &aesHeaderProtector{
		block:        block,
		mask:         make([]byte, block.BlockSize()),
		isLongHeader: isLongHeader,
	}
}

func (p *aesHeaderProtector) DecryptHeader(sample []byte, firstByte *byte, hdrBytes []byte) {
	p.apply(sample, firstByte, hdrBytes)
}

func (p *aesHeaderProtector) EncryptHeader(sample []byte, firstByte *byte, hdrBytes []byte) {
	p.apply(sample, firstByte, hdrBytes)
}

func (p *aesHeaderProtector) apply(sample []byte, firstByte *byte, hdrBytes []byte) {
	if len(sample) != len(p.mask) {
		panic("invalid sample size")
	}
	p.block.Encrypt(p.mask, sample)
	if p.isLongHeader {
		*firstByte ^= p.mask[0] & 0xf
	} else {
		*firstByte ^= p.mask[0] & 0x1f
	}
	for i := range hdrBytes {
		hdrBytes[i] ^= p.mask[i+1]
	}
}
