package handshake

import (
	"crypto"
	"crypto/cipher"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/qerr"
	"github.com/quic-go/quic-go/internal/utils"
	"github.com/quic-go/quic-go/logging"
)

func keyUpdateInterval() uint64 {
	// Reparsing the environment variable is not very performant, but it's only done in tests.
	if testing.Testing() {
		if v, err := strconv.ParseUint(os.Getenv("QUIC_GO_TEST_KEY_UPDATE_INTERVAL"), 10, 64); err == nil {
			return v
		}
	}
	return protocol.KeyUpdateInterval
}

// FirstKeyUpdateInterval is the maximum number of packets we send or receive before initiating the first key update.
// It's a package-level variable to allow modifying it for testing purposes.
var FirstKeyUpdateInterval uint64 = 100

type updatableAEAD struct {
	suite *cipherSuite

	keyPhase           protocol.KeyPhase
	largestAcked       protocol.PacketNumber
	firstPacketNumber  protocol.PacketNumber
	handshakeConfirmed bool

	invalidPacketLimit uint64
	invalidPacketCount uint64

	// Time when the keys should be dropped. Keys are dropped on the next call to Open().
	prevRcvAEADExpiry time.Time
	prevRcvAEAD       cipher.AEAD

	firstRcvdWithCurrentKey protocol.PacketNumber
	firstSentWithCurrentKey protocol.PacketNumber
	highestRcvdPN           protocol.PacketNumber // highest packet number received (which could be successfully unprotected)
	numRcvdWithCurrentKey   uint64
	numSentWithCurrentKey   uint64
	rcvAEAD                 cipher.AEAD
	sendAEAD                cipher.AEAD
	// caches cipher.AEAD.Overhead(). This speeds up calls to Overhead().
	aeadOverhead int

	nextRcvAEAD           cipher.AEAD
	nextSendAEAD          cipher.AEAD
	nextRcvTrafficSecret  []byte
	nextSendTrafficSecret []byte

	headerDecrypter headerProtector
	headerEncrypter headerProtector

	rttStats *utils.RTTStats

	tracer  *logging.ConnectionTracer
	logger  utils.Logger
	version protocol.Version

	// use a single slice to avoid allocations
	nonceBuf []byte

	multipathEnabled bool
	// logger field already exists from previous step, ensure it's correctly initialized if needed again.

	nextKeyUpdateTime time.Time
	ptoProvider       func() time.Duration
}

var (
	_ ShortHeaderOpener = &updatableAEAD{}
	_ ShortHeaderSealer = &updatableAEAD{}
)

func newUpdatableAEAD(rttStats *utils.RTTStats, tracer *logging.ConnectionTracer, logger utils.Logger, version protocol.Version, multipathEnabled bool, ptoProvider func() time.Duration) *updatableAEAD {
	return &updatableAEAD{
		firstPacketNumber:       protocol.InvalidPacketNumber,
		largestAcked:            protocol.InvalidPacketNumber,
		logger:                  logger, // Already initialized by previous step, ensure it's correct
		multipathEnabled:        multipathEnabled,
		firstRcvdWithCurrentKey: protocol.InvalidPacketNumber,
		firstSentWithCurrentKey: protocol.InvalidPacketNumber,
		rttStats:                rttStats, // Still used for prevRcvAEADExpiry, might be removable if ptoProvider covers all
		tracer:                  tracer,
		version:                 version,
		ptoProvider:             ptoProvider,
		// logger field already exists and is set.
	}
}

func (a *updatableAEAD) rollKeys() {
	if a.prevRcvAEAD != nil {
		a.logger.Debugf("Dropping key phase %d ahead of scheduled time. Drop time was: %s", a.keyPhase-1, a.prevRcvAEADExpiry)
		if a.tracer != nil && a.tracer.DroppedKey != nil {
			a.tracer.DroppedKey(a.keyPhase - 1)
		}
		a.prevRcvAEADExpiry = time.Time{}
	}

	a.keyPhase++
	a.firstRcvdWithCurrentKey = protocol.InvalidPacketNumber
	a.firstSentWithCurrentKey = protocol.InvalidPacketNumber
	a.numRcvdWithCurrentKey = 0
	a.numSentWithCurrentKey = 0
	a.prevRcvAEAD = a.rcvAEAD
	a.rcvAEAD = a.nextRcvAEAD
	a.sendAEAD = a.nextSendAEAD

	a.nextRcvTrafficSecret = a.getNextTrafficSecret(a.suite.Hash, a.nextRcvTrafficSecret)
	a.nextSendTrafficSecret = a.getNextTrafficSecret(a.suite.Hash, a.nextSendTrafficSecret)
	a.nextRcvAEAD = createAEAD(a.suite, a.nextRcvTrafficSecret, a.version)
	a.nextSendAEAD = createAEAD(a.suite, a.nextSendTrafficSecret, a.version)

	if a.ptoProvider != nil {
		largestPTO := a.ptoProvider()
		a.nextKeyUpdateTime = time.Now().Add(3 * largestPTO)
		a.logger.Debugf("Key update initiated. Next update possible after %s (3 * %s)", a.nextKeyUpdateTime.Format(time.RFC3339), largestPTO)
	} else {
		// Fallback if ptoProvider is not set, though it should be.
		// This might happen if called before cryptoSetup has fully initialized it.
		// Or, if this AEAD instance is not the 1-RTT one.
		// The original rttStats based PTO is still used for prevRcvAEADExpiry.
		// For nextKeyUpdateTime, we might log a warning or use a default fixed delay.
		a.logger.Warnf("ptoProvider not set during rollKeys; nextKeyUpdateTime based on default RTT stats PTO")
		if a.rttStats != nil { // Should always be set
			a.nextKeyUpdateTime = time.Now().Add(3 * a.rttStats.PTO(true))
		} else {
			// Highly unlikely, but as a last resort, use a fixed sensible default.
			a.nextKeyUpdateTime = time.Now().Add(3 * protocol.DefaultProbeTimeout)
		}
	}
}

func (a *updatableAEAD) startKeyDropTimer(now time.Time) {
	// Use the local rttStats for dropping old keys, as this is about local timer for local AEAD.
	// The largestOverallPTO is for coordinating *initiation* of new keys across paths.
	d := 3 * a.rttStats.PTO(true)
	a.logger.Debugf("Starting key drop timer to drop key phase %d (in %s)", a.keyPhase-1, d)
	a.prevRcvAEADExpiry = now.Add(d)
}

func (a *updatableAEAD) getNextTrafficSecret(hash crypto.Hash, ts []byte) []byte {
	return hkdfExpandLabel(hash, ts, []byte{}, "quic ku", hash.Size())
}

// SetReadKey sets the read key.
// For the client, this function is called before SetWriteKey.
// For the server, this function is called after SetWriteKey.
func (a *updatableAEAD) SetReadKey(suite *cipherSuite, trafficSecret []byte) {
	a.rcvAEAD = createAEAD(suite, trafficSecret, a.version)
	a.headerDecrypter = newHeaderProtector(suite, trafficSecret, false, a.version)
	if a.suite == nil {
		a.setAEADParameters(a.rcvAEAD, suite)
	}

	a.nextRcvTrafficSecret = a.getNextTrafficSecret(suite.Hash, trafficSecret)
	a.nextRcvAEAD = createAEAD(suite, a.nextRcvTrafficSecret, a.version)
}

// SetWriteKey sets the write key.
// For the client, this function is called after SetReadKey.
// For the server, this function is called before SetReadKey.
func (a *updatableAEAD) SetWriteKey(suite *cipherSuite, trafficSecret []byte) {
	a.sendAEAD = createAEAD(suite, trafficSecret, a.version)
	a.headerEncrypter = newHeaderProtector(suite, trafficSecret, false, a.version)
	if a.suite == nil {
		a.setAEADParameters(a.sendAEAD, suite)
	}

	a.nextSendTrafficSecret = a.getNextTrafficSecret(suite.Hash, trafficSecret)
	a.nextSendAEAD = createAEAD(suite, a.nextSendTrafficSecret, a.version)
}

func (a *updatableAEAD) setAEADParameters(aead cipher.AEAD, suite *cipherSuite) {
	a.nonceBuf = make([]byte, aead.NonceSize())
	a.aeadOverhead = aead.Overhead()
	a.suite = suite
	switch suite.ID {
	case tls.TLS_AES_128_GCM_SHA256, tls.TLS_AES_256_GCM_SHA384:
		a.invalidPacketLimit = protocol.InvalidPacketLimitAES
	case tls.TLS_CHACHA20_POLY1305_SHA256:
		a.invalidPacketLimit = protocol.InvalidPacketLimitChaCha
	default:
		panic(fmt.Sprintf("unknown cipher suite %d", suite.ID))
	}
}

func (a *updatableAEAD) DecodePacketNumber(wirePN protocol.PacketNumber, wirePNLen protocol.PacketNumberLen) protocol.PacketNumber {
	return protocol.DecodePacketNumber(wirePNLen, a.highestRcvdPN, wirePN)
}

func (a *updatableAEAD) Open(dst, src []byte, rcvTime time.Time, pn protocol.PacketNumber, pathID uint64, kp protocol.KeyPhaseBit, ad []byte) ([]byte, error) {
	dec, err := a.open(dst, src, rcvTime, pn, pathID, kp, ad)
	if err == ErrDecryptionFailed {
		a.invalidPacketCount++
		if a.invalidPacketCount >= a.invalidPacketLimit {
			return nil, &qerr.TransportError{ErrorCode: qerr.AEADLimitReached}
		}
	}
	if err == nil {
		a.highestRcvdPN = max(a.highestRcvdPN, pn)
	}
	return dec, err
}

func (a *updatableAEAD) open(dst, src []byte, rcvTime time.Time, pn protocol.PacketNumber, pathID uint64, kp protocol.KeyPhaseBit, ad []byte) ([]byte, error) {
	if a.prevRcvAEAD != nil && !a.prevRcvAEADExpiry.IsZero() && rcvTime.After(a.prevRcvAEADExpiry) {
		a.prevRcvAEAD = nil
		a.logger.Debugf("Dropping key phase %d", a.keyPhase-1)
		a.prevRcvAEADExpiry = time.Time{}
		if a.tracer != nil && a.tracer.DroppedKey != nil {
			a.tracer.DroppedKey(a.keyPhase - 1)
		}
	}

	var currentNonce []byte
	if a.multipathEnabled {
		nonce := make([]byte, len(a.nonceBuf))
		iv := a.suite.IV()

		var pathAndPacketNumberBytes [12]byte
		binary.BigEndian.PutUint32(pathAndPacketNumberBytes[0:4], uint32(pathID))
		maskedPN := pn & 0x3FFFFFFFFFFFFFFF // Keep lower 62 bits
		binary.BigEndian.PutUint64(pathAndPacketNumberBytes[4:12], maskedPN)

		copy(nonce[len(nonce)-12:], pathAndPacketNumberBytes[:])
		for i := 0; i < len(nonce); i++ {
			nonce[i] ^= iv[i]
		}
		if a.logger.Debug() {
			a.logger.Debugf("Multipath AEAD Open: PathID: %d, PN: %d, Nonce: %x", pathID, pn, nonce)
		}
		currentNonce = nonce
	} else {
		binary.BigEndian.PutUint64(a.nonceBuf[len(a.nonceBuf)-8:], uint64(pn))
		currentNonce = a.nonceBuf
	}

	if kp != a.keyPhase.Bit() {
		if a.keyPhase > 0 && a.firstRcvdWithCurrentKey == protocol.InvalidPacketNumber || pn < a.firstRcvdWithCurrentKey {
			if a.prevRcvAEAD == nil {
				return nil, ErrKeysDropped
			}
			// we updated the key, but the peer hasn't updated yet
			dec, err := a.prevRcvAEAD.Open(dst, currentNonce, src, ad)
			if err != nil {
				err = ErrDecryptionFailed
			}
			return dec, err
		}
		// try opening the packet with the next key phase
		dec, err := a.nextRcvAEAD.Open(dst, currentNonce, src, ad)
		if err != nil {
			return nil, ErrDecryptionFailed
		}
		// Opening succeeded. Check if the peer was allowed to update.
		if a.keyPhase > 0 && a.firstSentWithCurrentKey == protocol.InvalidPacketNumber {
			return nil, &qerr.TransportError{
				ErrorCode:    qerr.KeyUpdateError,
				ErrorMessage: "keys updated too quickly",
			}
		}
		a.rollKeys()
		a.logger.Debugf("Peer updated keys to %d", a.keyPhase)
		// The peer initiated this key update. It's safe to drop the keys for the previous generation now.
		// Start a timer to drop the previous key generation.
		a.startKeyDropTimer(rcvTime)
		if a.tracer != nil && a.tracer.UpdatedKey != nil {
			a.tracer.UpdatedKey(a.keyPhase, true)
		}
		a.firstRcvdWithCurrentKey = pn
		return dec, err
	}
	// The AEAD we're using here will be the qtls.aeadAESGCM13.
	// It uses the nonce provided here and XOR it with the IV.
	dec, err := a.rcvAEAD.Open(dst, currentNonce, src, ad)
	if err != nil {
		return dec, ErrDecryptionFailed
	}
	a.numRcvdWithCurrentKey++
	if a.firstRcvdWithCurrentKey == protocol.InvalidPacketNumber {
		// We initiated the key updated, and now we received the first packet protected with the new key phase.
		// Therefore, we are certain that the peer rolled its keys as well. Start a timer to drop the old keys.
		if a.keyPhase > 0 {
			a.logger.Debugf("Peer confirmed key update to phase %d", a.keyPhase)
			a.startKeyDropTimer(rcvTime)
		}
		a.firstRcvdWithCurrentKey = pn
	}
	return dec, err
}

func (a *updatableAEAD) Seal(dst, src []byte, pn protocol.PacketNumber, pathID uint64, ad []byte) []byte {
	if a.firstSentWithCurrentKey == protocol.InvalidPacketNumber {
		a.firstSentWithCurrentKey = pn
	}
	if a.firstPacketNumber == protocol.InvalidPacketNumber {
		a.firstPacketNumber = pn
	}
	a.numSentWithCurrentKey++

	if a.multipathEnabled {
		nonce := make([]byte, len(a.nonceBuf))
		// IV is already stored in a.nonceBuf by setAEADParameters which copies suite.IV()
		// For multipath, the IV from the cipher suite is used directly.
		// The packet number and path ID are XORed with this IV.
		iv := a.suite.IV()

		var pathAndPacketNumberBytes [12]byte
		binary.BigEndian.PutUint32(pathAndPacketNumberBytes[0:4], uint32(pathID))
		maskedPN := pn & 0x3FFFFFFFFFFFFFFF // Keep lower 62 bits
		binary.BigEndian.PutUint64(pathAndPacketNumberBytes[4:12], maskedPN)

		// Left-pad pathAndPacketNumberBytes with zeros if nonce size > 12
		copy(nonce[len(nonce)-12:], pathAndPacketNumberBytes[:])

		for i := 0; i < len(nonce); i++ {
			nonce[i] ^= iv[i]
		}
		if a.logger.Debug() {
			a.logger.Debugf("Multipath AEAD Seal: PathID: %d, PN: %d, Nonce: %x", pathID, pn, nonce)
		}
		return a.sendAEAD.Seal(dst, nonce, src, ad)
	}

	// Original nonce calculation for non-multipath
	binary.BigEndian.PutUint64(a.nonceBuf[len(a.nonceBuf)-8:], uint64(pn))
	// The AEAD we're using here will be the qtls.aeadAESGCM13.
	// It uses the nonce provided here and XOR it with the IV.
	return a.sendAEAD.Seal(dst, a.nonceBuf, src, ad)
}

func (a *updatableAEAD) SetLargestAcked(pn protocol.PacketNumber) error {
	if a.firstSentWithCurrentKey != protocol.InvalidPacketNumber &&
		pn >= a.firstSentWithCurrentKey && a.numRcvdWithCurrentKey == 0 {
		return &qerr.TransportError{
			ErrorCode:    qerr.KeyUpdateError,
			ErrorMessage: fmt.Sprintf("received ACK for key phase %d, but peer didn't update keys", a.keyPhase),
		}
	}
	a.largestAcked = pn
	return nil
}

func (a *updatableAEAD) SetHandshakeConfirmed() {
	a.handshakeConfirmed = true
}

func (a *updatableAEAD) updateAllowed() bool {
	if !a.handshakeConfirmed {
		return false
	}
	// the first key update is allowed as soon as the handshake is confirmed
	return a.keyPhase == 0 ||
		// subsequent key updates as soon as a packet sent with that key phase has been acknowledged
		(a.firstSentWithCurrentKey != protocol.InvalidPacketNumber &&
			a.largestAcked != protocol.InvalidPacketNumber &&
			a.largestAcked >= a.firstSentWithCurrentKey)
}

func (a *updatableAEAD) shouldInitiateKeyUpdate() bool {
	if !a.updateAllowed() {
		return false
	}
	if !a.nextKeyUpdateTime.IsZero() && time.Now().Before(a.nextKeyUpdateTime) {
		a.logger.Debugf("Key update cool-down period active. Next update possible after %s", a.nextKeyUpdateTime.Format(time.RFC3339))
		return false
	}
	// Initiate the first key update shortly after the handshake, in order to exercise the key update mechanism.
	if a.keyPhase == 0 {
		if a.numRcvdWithCurrentKey >= FirstKeyUpdateInterval || a.numSentWithCurrentKey >= FirstKeyUpdateInterval {
			return true
		}
	}
	if a.numRcvdWithCurrentKey >= keyUpdateInterval() {
		a.logger.Debugf("Received %d packets with current key phase. Initiating key update to the next key phase: %d", a.numRcvdWithCurrentKey, a.keyPhase+1)
		return true
	}
	if a.numSentWithCurrentKey >= keyUpdateInterval() {
		a.logger.Debugf("Sent %d packets with current key phase. Initiating key update to the next key phase: %d", a.numSentWithCurrentKey, a.keyPhase+1)
		return true
	}
	return false
}

func (a *updatableAEAD) KeyPhase() protocol.KeyPhaseBit {
	if a.shouldInitiateKeyUpdate() {
		a.rollKeys()
		a.logger.Debugf("Initiating key update to key phase %d", a.keyPhase)
		if a.tracer != nil && a.tracer.UpdatedKey != nil {
			a.tracer.UpdatedKey(a.keyPhase, false)
		}
	}
	return a.keyPhase.Bit()
}

func (a *updatableAEAD) Overhead() int {
	return a.aeadOverhead
}

func (a *updatableAEAD) EncryptHeader(sample []byte, firstByte *byte, hdrBytes []byte) {
	a.headerEncrypter.EncryptHeader(sample, firstByte, hdrBytes)
}

func (a *updatableAEAD) DecryptHeader(sample []byte, firstByte *byte, hdrBytes []byte) {
	a.headerDecrypter.DecryptHeader(sample, firstByte, hdrBytes)
}

func (a *updatableAEAD) FirstPacketNumber() protocol.PacketNumber {
	return a.firstPacketNumber
}

// SetMultipathEnabled sets the multipathEnabled flag.
func (a *updatableAEAD) SetMultipathEnabled(enabled bool) {
	a.multipathEnabled = enabled
}
