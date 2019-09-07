package handshake

import (
	"crypto/cipher"
	"encoding/binary"

	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/marten-seemann/qtls"
)

type sealer struct {
	aead            cipher.AEAD
	headerProtector headerProtector

	// use a single slice to avoid allocations
	nonceBuf []byte
}

var _ LongHeaderSealer = &sealer{}

func newLongHeaderSealer(aead cipher.AEAD, headerProtector headerProtector) LongHeaderSealer {
	return &sealer{
		aead:            aead,
		headerProtector: headerProtector,
		nonceBuf:        make([]byte, aead.NonceSize()),
	}
}

func (s *sealer) Seal(dst, src []byte, pn protocol.PacketNumber, ad []byte) []byte {
	binary.BigEndian.PutUint64(s.nonceBuf[len(s.nonceBuf)-8:], uint64(pn))
	// The AEAD we're using here will be the qtls.aeadAESGCM13.
	// It uses the nonce provided here and XOR it with the IV.
	return s.aead.Seal(dst, s.nonceBuf, src, ad)
}

func (s *sealer) EncryptHeader(sample []byte, firstByte *byte, pnBytes []byte) {
	s.headerProtector.EncryptHeader(sample, firstByte, pnBytes)
}

func (s *sealer) Overhead() int {
	return s.aead.Overhead()
}

type longHeaderOpener struct {
	aead            cipher.AEAD
	headerProtector headerProtector

	// use a single slice to avoid allocations
	nonceBuf []byte
}

var _ LongHeaderOpener = &longHeaderOpener{}

func newLongHeaderOpener(aead cipher.AEAD, headerProtector headerProtector) LongHeaderOpener {
	return &longHeaderOpener{
		aead:            aead,
		headerProtector: headerProtector,
		nonceBuf:        make([]byte, aead.NonceSize()),
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
	o.headerProtector.DecryptHeader(sample, firstByte, pnBytes)
}

func createAEAD(suite *qtls.CipherSuiteTLS13, trafficSecret []byte) cipher.AEAD {
	key := qtls.HkdfExpandLabel(suite.Hash, trafficSecret, []byte{}, "quic key", suite.KeyLen)
	iv := qtls.HkdfExpandLabel(suite.Hash, trafficSecret, []byte{}, "quic iv", suite.IVLen())
	return suite.AEAD(key, iv)
}
