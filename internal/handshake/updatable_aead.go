package handshake

import (
	"crypto"
	"crypto/cipher"
	"encoding/binary"

	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/marten-seemann/qtls"
)

type updatableAEAD struct {
	suite cipherSuite

	keyPhase protocol.KeyPhase

	prevRcvAEAD cipher.AEAD

	firstRcvdWithCurrentKey protocol.PacketNumber
	firstSentWithCurrentKey protocol.PacketNumber
	rcvAEAD                 cipher.AEAD
	sendAEAD                cipher.AEAD

	nextRcvAEAD           cipher.AEAD
	nextSendAEAD          cipher.AEAD
	nextRcvTrafficSecret  []byte
	nextSendTrafficSecret []byte

	hpDecrypter cipher.Block
	hpEncrypter cipher.Block

	// use a single slice to avoid allocations
	nonceBuf []byte
	hpMask   []byte
}

var _ ShortHeaderOpener = &updatableAEAD{}
var _ ShortHeaderSealer = &updatableAEAD{}

func newUpdatableAEAD() *updatableAEAD {
	return &updatableAEAD{
		firstRcvdWithCurrentKey: protocol.InvalidPacketNumber,
		firstSentWithCurrentKey: protocol.InvalidPacketNumber,
	}
}

func (a *updatableAEAD) rollKeys() {
	a.firstRcvdWithCurrentKey = protocol.InvalidPacketNumber
	a.firstSentWithCurrentKey = protocol.InvalidPacketNumber
	a.keyPhase = a.keyPhase.Next()
	a.prevRcvAEAD = a.rcvAEAD
	a.rcvAEAD = a.nextRcvAEAD
	a.sendAEAD = a.nextSendAEAD

	a.nextRcvTrafficSecret = a.getNextTrafficSecret(a.suite.Hash(), a.nextRcvTrafficSecret)
	a.nextSendTrafficSecret = a.getNextTrafficSecret(a.suite.Hash(), a.nextSendTrafficSecret)
	a.nextRcvAEAD, _ = createAEAD(a.suite, a.nextRcvTrafficSecret)
	a.nextSendAEAD, _ = createAEAD(a.suite, a.nextSendTrafficSecret)
}

func (a *updatableAEAD) getNextTrafficSecret(hash crypto.Hash, ts []byte) []byte {
	return qtls.HkdfExpandLabel(hash, ts, []byte{}, "traffic upd", hash.Size())
}

// For the client, this function is called before SetWriteKey.
// For the server, this function is called after SetWriteKey.
func (a *updatableAEAD) SetReadKey(suite cipherSuite, trafficSecret []byte) {
	a.rcvAEAD, a.hpDecrypter = createAEAD(suite, trafficSecret)
	if a.suite == nil {
		a.nonceBuf = make([]byte, a.rcvAEAD.NonceSize())
		a.hpMask = make([]byte, a.hpDecrypter.BlockSize())
		a.suite = suite
	}

	a.nextRcvTrafficSecret = a.getNextTrafficSecret(suite.Hash(), trafficSecret)
	a.nextRcvAEAD, _ = createAEAD(suite, a.nextRcvTrafficSecret)
}

// For the client, this function is called after SetReadKey.
// For the server, this function is called before SetWriteKey.
func (a *updatableAEAD) SetWriteKey(suite cipherSuite, trafficSecret []byte) {
	a.sendAEAD, a.hpEncrypter = createAEAD(suite, trafficSecret)
	if a.suite == nil {
		a.nonceBuf = make([]byte, a.sendAEAD.NonceSize())
		a.hpMask = make([]byte, a.hpEncrypter.BlockSize())
		a.suite = suite
	}

	a.nextSendTrafficSecret = a.getNextTrafficSecret(suite.Hash(), trafficSecret)
	a.nextSendAEAD, _ = createAEAD(suite, a.nextSendTrafficSecret)
}

func (a *updatableAEAD) Open(dst, src []byte, pn protocol.PacketNumber, kp protocol.KeyPhase, ad []byte) ([]byte, error) {
	binary.BigEndian.PutUint64(a.nonceBuf[len(a.nonceBuf)-8:], uint64(pn))
	if kp != a.keyPhase {
		if a.firstRcvdWithCurrentKey == protocol.InvalidPacketNumber || pn < a.firstRcvdWithCurrentKey {
			// TODO: check that prevRcv actually exists
			// we updated the key, but the peer hasn't updated yet
			dec, err := a.prevRcvAEAD.Open(dst, a.nonceBuf, src, ad)
			if err != nil {
				err = ErrDecryptionFailed
			}
			return dec, err
		}
		// try opening the packet with the next key phase
		dec, err := a.nextRcvAEAD.Open(dst, a.nonceBuf, src, ad)
		if err != nil {
			err = ErrDecryptionFailed
		} else {
			// if opening succeeds, roll over to the next key phase
			a.rollKeys()
			a.firstRcvdWithCurrentKey = pn
		}
		return dec, err
	}
	// The AEAD we're using here will be the qtls.aeadAESGCM13.
	// It uses the nonce provided here and XOR it with the IV.
	dec, err := a.rcvAEAD.Open(dst, a.nonceBuf, src, ad)
	if err != nil {
		err = ErrDecryptionFailed
	} else if a.firstRcvdWithCurrentKey == protocol.InvalidPacketNumber {
		a.firstRcvdWithCurrentKey = pn
	}
	return dec, err
}

func (a *updatableAEAD) Seal(dst, src []byte, pn protocol.PacketNumber, ad []byte) []byte {
	if a.firstSentWithCurrentKey == protocol.InvalidPacketNumber {
		a.firstSentWithCurrentKey = pn
	}
	binary.BigEndian.PutUint64(a.nonceBuf[len(a.nonceBuf)-8:], uint64(pn))
	// The AEAD we're using here will be the qtls.aeadAESGCM13.
	// It uses the nonce provided here and XOR it with the IV.
	return a.sendAEAD.Seal(dst, a.nonceBuf, src, ad)
}

func (a *updatableAEAD) KeyPhase() protocol.KeyPhase {
	return a.keyPhase
}

func (a *updatableAEAD) Overhead() int {
	return a.sendAEAD.Overhead()
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
