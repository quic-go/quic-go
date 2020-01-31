package handshake

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"

	"github.com/marten-seemann/chacha20"
	"github.com/marten-seemann/qtls"
)

type headerProtector interface {
	EncryptHeader(sample []byte, firstByte *byte, hdrBytes []byte)
	DecryptHeader(sample []byte, firstByte *byte, hdrBytes []byte)
}

func newHeaderProtector(suite *qtls.CipherSuiteTLS13, trafficSecret []byte, isLongHeader bool) headerProtector {
	switch suite.ID {
	case qtls.TLS_AES_128_GCM_SHA256, qtls.TLS_AES_256_GCM_SHA384:
		return newAESHeaderProtector(suite, trafficSecret, isLongHeader)
	case qtls.TLS_CHACHA20_POLY1305_SHA256:
		return newChaChaHeaderProtector(suite, trafficSecret, isLongHeader)
	default:
		panic(fmt.Sprintf("Invalid cipher suite id: %d", suite.ID))
	}

}

type aesHeaderProtector struct {
	mask         []byte
	block        cipher.Block
	isLongHeader bool
}

var _ headerProtector = &aesHeaderProtector{}

func newAESHeaderProtector(suite *qtls.CipherSuiteTLS13, trafficSecret []byte, isLongHeader bool) headerProtector {
	hpKey := qtls.HkdfExpandLabel(suite.Hash, trafficSecret, []byte{}, "quic hp", suite.KeyLen)
	block, err := aes.NewCipher(hpKey)
	if err != nil {
		panic(fmt.Sprintf("error creating new AES cipher: %s", err))
	}
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

type chachaHeaderProtector struct {
	mask [5]byte

	key          [32]byte
	sampleBuf    [16]byte
	isLongHeader bool
}

var _ headerProtector = &chachaHeaderProtector{}

func newChaChaHeaderProtector(suite *qtls.CipherSuiteTLS13, trafficSecret []byte, isLongHeader bool) headerProtector {
	hpKey := qtls.HkdfExpandLabel(suite.Hash, trafficSecret, []byte{}, "quic hp", suite.KeyLen)

	p := &chachaHeaderProtector{
		isLongHeader: isLongHeader,
	}
	copy(p.key[:], hpKey)
	return p
}

func (p *chachaHeaderProtector) DecryptHeader(sample []byte, firstByte *byte, hdrBytes []byte) {
	// Workaround for https://github.com/lucas-clemente/quic-go/issues/2326.
	// The ChaCha20 implementation panics when the nonce is 0xffffffff.
	// Don't apply header protection in that case.
	// The packet will end up undecryptable, but it only applies to 1 in 2^32 packets.
	if sample[0] == 0xff && sample[1] == 0xff && sample[2] == 0xff && sample[3] == 0xff {
		return
	}
	p.apply(sample, firstByte, hdrBytes)
}

func (p *chachaHeaderProtector) EncryptHeader(sample []byte, firstByte *byte, hdrBytes []byte) {
	// Workaround for https://github.com/lucas-clemente/quic-go/issues/2326.
	// The ChaCha20 implementation panics when the nonce is 0xffffffff.
	// Apply header protection with a random mask, in order to not leak any data.
	// The packet will end up undecryptable, but this only applies to 1 in 2^32 packets.
	if sample[0] == 0xff && sample[1] == 0xff && sample[2] == 0xff && sample[3] == 0xff {
		if _, err := rand.Read(p.mask[:]); err != nil {
			panic("couldn't get rand for ChaCha20 bug workaround")
		}
		p.applyMask(firstByte, hdrBytes)
	}
	p.apply(sample, firstByte, hdrBytes)
}

func (p *chachaHeaderProtector) apply(sample []byte, firstByte *byte, hdrBytes []byte) {
	if len(sample) < len(p.mask) {
		panic("invalid sample size")
	}
	for i := 0; i < 5; i++ {
		p.mask[i] = 0
	}
	copy(p.sampleBuf[:], sample)
	chacha20.XORKeyStream(p.mask[:], p.mask[:], &p.sampleBuf, &p.key)
	p.applyMask(firstByte, hdrBytes)
}

func (p *chachaHeaderProtector) applyMask(firstByte *byte, hdrBytes []byte) {
	if p.isLongHeader {
		*firstByte ^= p.mask[0] & 0xf
	} else {
		*firstByte ^= p.mask[0] & 0x1f
	}
	for i := range hdrBytes {
		hdrBytes[i] ^= p.mask[i+1]
	}
}
