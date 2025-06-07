package quic

import (
	crand "crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"math/rand/v2"
	"time"

	"github.com/quic-go/quic-go/internal/ackhandler"
	"github.com/quic-go/quic-go/internal/handshake"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/qerr"
	"github.com/quic-go/quic-go/internal/wire"
)

var errNothingToPack = errors.New("nothing to pack")

// quicPath is an interface that represents the subset of multipath_manager.quicPath
// methods needed by the packetPacker.
type quicPath interface {
	PacketNumberGenerator() *ackhandler.PacketNumberGenerator
	SentPacketHandler() ackhandler.SentPacketHandler // For ECNMode
	// TODO: Add OurConnectionID() and PeerConnectionID() if CIDs are fetched via this interface
}

type packer interface {
	PackCoalescedPacket(onlyAck bool, maxPacketSize protocol.ByteCount, now time.Time, v protocol.Version) (*coalescedPacket, error)
	PackAckOnlyPacket(maxPacketSize protocol.ByteCount, pathID protocol.PathID, destConnID protocol.ConnectionID, ecn protocol.ECN, now time.Time, v protocol.Version) (shortHeaderPacket, *packetBuffer, error)
	AppendPacket(buf *packetBuffer, maxPacketSize protocol.ByteCount, pathID protocol.PathID, destConnID protocol.ConnectionID, ecn protocol.ECN, now time.Time, v protocol.Version) (shortHeaderPacket, error)
	PackPTOProbePacket(encLevel protocol.EncryptionLevel, maxPacketSize protocol.ByteCount, addPingIfEmpty bool, pathID protocol.PathID, destConnID protocol.ConnectionID, now time.Time, v protocol.Version) (*coalescedPacket, error)
	PackConnectionClose(*qerr.TransportError, protocol.ByteCount, protocol.Version) (*coalescedPacket, error)
	PackApplicationClose(*qerr.ApplicationError, protocol.ByteCount, protocol.Version) (*coalescedPacket, error)
	PackPathProbePacket(pathID protocol.PathID, packetDestConnID protocol.ConnectionID, frames []ackhandler.Frame, v protocol.Version) (shortHeaderPacket, *packetBuffer, error)
	PackMTUProbePacket(ping ackhandler.Frame, size protocol.ByteCount, pathID protocol.PathID, destConnID protocol.ConnectionID, v protocol.Version) (shortHeaderPacket, *packetBuffer, error)
	SetToken([]byte)
}

type sealer interface {
	handshake.LongHeaderSealer
}

type payload struct {
	streamFrames []ackhandler.StreamFrame
	frames       []ackhandler.Frame
	ack          *wire.AckFrame
	length       protocol.ByteCount
}

type longHeaderPacket struct {
	header       *wire.ExtendedHeader
	ack          *wire.AckFrame
	frames       []ackhandler.Frame
	streamFrames []ackhandler.StreamFrame
	length       protocol.ByteCount
}

type shortHeaderPacket struct {
	PacketNumber         protocol.PacketNumber
	Frames               []ackhandler.Frame
	StreamFrames         []ackhandler.StreamFrame
	Ack                  *wire.AckFrame
	Length               protocol.ByteCount
	IsPathMTUProbePacket bool
	IsPathProbePacket    bool
	DestConnID           protocol.ConnectionID
	PacketNumberLen      protocol.PacketNumberLen
	KeyPhase             protocol.KeyPhaseBit
}

func (p *shortHeaderPacket) IsAckEliciting() bool { return ackhandler.HasAckElicitingFrames(p.Frames) }

type coalescedPacket struct {
	buffer         *packetBuffer
	longHdrPackets []*longHeaderPacket
	shortHdrPacket *shortHeaderPacket
}

func (p *coalescedPacket) IsOnlyShortHeaderPacket() bool {
	return len(p.longHdrPackets) == 0 && p.shortHdrPacket != nil
}
func (p *longHeaderPacket) EncryptionLevel() protocol.EncryptionLevel {
	switch p.header.Type {
	case protocol.PacketTypeInitial: return protocol.EncryptionInitial
	case protocol.PacketTypeHandshake: return protocol.EncryptionHandshake
	case protocol.PacketType0RTT: return protocol.Encryption0RTT
	default: panic("can't determine encryption level")
	}
}
func (p *longHeaderPacket) IsAckEliciting() bool { return ackhandler.HasAckElicitingFrames(p.frames) }

type packetNumberManager interface {
	PeekPacketNumber(protocol.EncryptionLevel) (protocol.PacketNumber, protocol.PacketNumberLen)
	PopPacketNumber(protocol.EncryptionLevel) protocol.PacketNumber
}
type sealingManager interface {
	GetInitialSealer() (handshake.LongHeaderSealer, error)
	GetHandshakeSealer() (handshake.LongHeaderSealer, error)
	Get0RTTSealer() (handshake.LongHeaderSealer, error)
	Get1RTTSealer() (handshake.ShortHeaderSealer, error)
}
type frameSource interface {
	HasData() bool
	Append([]ackhandler.Frame, []ackhandler.StreamFrame, protocol.ByteCount, time.Time, protocol.Version) ([]ackhandler.Frame, []ackhandler.StreamFrame, protocol.ByteCount)
}
type ackFrameSource interface {
	GetAckFrame(_ protocol.EncryptionLevel, now time.Time, onlyIfQueued bool) *wire.AckFrame
}

type packetPacker struct {
	srcConnID     protocol.ConnectionID
	getDestConnID func() protocol.ConnectionID

	perspective protocol.Perspective
	cryptoSetup sealingManager

	initialStream   *initialCryptoStream
	handshakeStream *cryptoStream

	token []byte

	pnManager           packetNumberManager
	framer              frameSource
	acks                ackFrameSource
	datagramQueue       *datagramQueue
	retransmissionQueue *retransmissionQueue
	rand                rand.Rand

	numNonAckElicitingAcks int

	multiPathMgr interface {
		ForEachActivePath(func(pathID protocol.PathID, rph ackhandler.ReceivedPacketHandler) (cont bool))
		GetPathForSending(pathID protocol.PathID) quicPath
	}
}

var _ packer = &packetPacker{}

func newPacketPacker(
	srcConnID protocol.ConnectionID, getDestConnID func() protocol.ConnectionID,
	initialStream *initialCryptoStream, handshakeStream *cryptoStream,
	packetNumberManager packetNumberManager, retransmissionQueue *retransmissionQueue,
	cryptoSetup sealingManager, framer frameSource, acks ackFrameSource,
	datagramQueue *datagramQueue, perspective protocol.Perspective,
	multiPathMgr interface {
		ForEachActivePath(func(pathID protocol.PathID, rph ackhandler.ReceivedPacketHandler) (cont bool))
		GetPathForSending(pathID protocol.PathID) quicPath
	},
) *packetPacker {
	var b [16]byte; _, _ = crand.Read(b[:])
	return &packetPacker{
		cryptoSetup: cryptoSetup, getDestConnID: getDestConnID, srcConnID: srcConnID,
		initialStream: initialStream, handshakeStream: handshakeStream,
		retransmissionQueue: retransmissionQueue, datagramQueue: datagramQueue,
		perspective: perspective, framer: framer, acks: acks,
		rand: *rand.New(rand.NewPCG(binary.BigEndian.Uint64(b[:8]), binary.BigEndian.Uint64(b[8:]))),
		pnManager: packetNumberManager, multiPathMgr: multiPathMgr,
	}
}

func (p *packetPacker) PackConnectionClose(e *qerr.TransportError, maxPacketSize protocol.ByteCount, v protocol.Version) (*coalescedPacket, error) {
	var reason string; if !e.ErrorCode.IsCryptoError() { reason = e.ErrorMessage }
	return p.packConnectionClose(false, uint64(e.ErrorCode), e.FrameType, reason, maxPacketSize, v)
}
func (p *packetPacker) PackApplicationClose(e *qerr.ApplicationError, maxPacketSize protocol.ByteCount, v protocol.Version) (*coalescedPacket, error) {
	return p.packConnectionClose(true, uint64(e.ErrorCode), 0, e.ErrorMessage, maxPacketSize, v)
}
func (p *packetPacker) packConnectionClose(
	isApplicationError bool, errorCode uint64, frameType uint64, reason string,
	maxPacketSize protocol.ByteCount, v protocol.Version,
) (*coalescedPacket, error) {
	var sealers [4]sealer; var hdrs [3]*wire.ExtendedHeader; var payloads [4]payload
	var size protocol.ByteCount; var connID protocol.ConnectionID
	var oneRTTPacketNumber protocol.PacketNumber; var oneRTTPacketNumberLen protocol.PacketNumberLen
	var keyPhase protocol.KeyPhaseBit; var numLongHdrPackets uint8
	encLevels := [4]protocol.EncryptionLevel{protocol.EncryptionInitial, protocol.EncryptionHandshake, protocol.Encryption0RTT, protocol.Encryption1RTT}
	for i, encLevel := range encLevels {
		if p.perspective == protocol.PerspectiveServer && encLevel == protocol.Encryption0RTT { continue }
		ccf := &wire.ConnectionCloseFrame{IsApplicationError: isApplicationError, ErrorCode: errorCode, FrameType: frameType, ReasonPhrase: reason}
		if isApplicationError && (encLevel == protocol.EncryptionInitial || encLevel == protocol.EncryptionHandshake) {
			ccf.IsApplicationError = false; ccf.ErrorCode = uint64(qerr.ApplicationErrorErrorCode); ccf.ReasonPhrase = ""
		}
		pl := payload{frames: []ackhandler.Frame{{Frame: ccf}}, length: ccf.Length(v)}
		var sealer sealer; var err error; var shortSealer handshake.ShortHeaderSealer
		switch encLevel {
		case protocol.EncryptionInitial: sealer, err = p.cryptoSetup.GetInitialSealer()
		case protocol.EncryptionHandshake: sealer, err = p.cryptoSetup.GetHandshakeSealer()
		case protocol.Encryption0RTT: sealer, err = p.cryptoSetup.Get0RTTSealer()
		case protocol.Encryption1RTT: var s handshake.ShortHeaderSealer; s, err = p.cryptoSetup.Get1RTTSealer(); if err == nil { keyPhase = s.KeyPhase(); shortSealer = s }; sealer = s
		}
		if err == handshake.ErrKeysNotYetAvailable || err == handshake.ErrKeysDropped { continue }
		if err != nil { return nil, err }
		sealers[i] = sealer; var hdr *wire.ExtendedHeader
		if encLevel == protocol.Encryption1RTT {
			connID = p.getDestConnID() // For CONNECTION_CLOSE, use default path DCID
			// PN for 1-RTT CONNECTION_CLOSE will be handled by appendShortHeaderPacket using pathID 0's PN generator
			oneRTTPacketNumber, oneRTTPacketNumberLen = p.pnManager.PeekPacketNumber(protocol.Encryption1RTT)
			size += p.shortHeaderPacketLength(connID, oneRTTPacketNumberLen, pl)
		} else {
			hdr = p.getLongHeader(encLevel, v); hdrs[i] = hdr
			size += p.longHeaderPacketLength(hdr, pl, v) + protocol.ByteCount(sealer.Overhead()); numLongHdrPackets++
		}
		payloads[i] = pl
	}
	buffer := getPacketBuffer()
	packet := &coalescedPacket{buffer: buffer, longHdrPackets: make([]*longHeaderPacket, 0, numLongHdrPackets)}
	for i, encLevel := range encLevels {
		if sealers[i] == nil { continue }
		if encLevel == protocol.Encryption1RTT {
			if shortSealer == nil { return nil, errors.New("packer BUG: ShortHeaderSealer not available for 1-RTT CONNECTION_CLOSE") }
			shp, err := p.appendShortHeaderPacket(buffer, connID, oneRTTPacketNumber, oneRTTPacketNumberLen, keyPhase, 0, payloads[i], 0, maxPacketSize, shortSealer, false, protocol.ECNUnsupported, v)
			if err != nil { return nil, err }
			packet.shortHdrPacket = &shp
		} else {
			var paddingLen protocol.ByteCount
			if encLevel == protocol.EncryptionInitial { paddingLen = p.initialPaddingLen(payloads[i].frames, size, maxPacketSize) }
			longHdrPacket, err := p.appendLongHeaderPacket(buffer, hdrs[i], payloads[i], paddingLen, encLevel, sealers[i], v)
			if err != nil { return nil, err }
			packet.longHdrPackets = append(packet.longHdrPackets, longHdrPacket)
		}
	}
	return packet, nil
}

func (p *packetPacker) longHeaderPacketLength(hdr *wire.ExtendedHeader, pl payload, v protocol.Version) protocol.ByteCount { /* ... */
	var paddingLen protocol.ByteCount
	pnLen := protocol.ByteCount(hdr.PacketNumberLen)
	if pl.length < 4-pnLen { paddingLen = 4 - pnLen - pl.length }
	return hdr.GetLength(v) + pl.length + paddingLen
}
func (p *packetPacker) shortHeaderPacketLength(connID protocol.ConnectionID, pnLen protocol.PacketNumberLen, pl payload) protocol.ByteCount { /* ... */
	var paddingLen protocol.ByteCount
	if pl.length < 4-protocol.ByteCount(pnLen) { paddingLen = 4 - protocol.ByteCount(pnLen) - pl.length }
	return wire.ShortHeaderLen(connID, pnLen) + pl.length + paddingLen
}
func (p *packetPacker) initialPaddingLen(frames []ackhandler.Frame, currentSize, maxPacketSize protocol.ByteCount) protocol.ByteCount { /* ... */
	if p.perspective == protocol.PerspectiveServer && !ackhandler.HasAckElicitingFrames(frames) { return 0 }
	if currentSize >= maxPacketSize { return 0 }
	return maxPacketSize - currentSize
}

func (p *packetPacker) PackCoalescedPacket(onlyAck bool, maxSize protocol.ByteCount, now time.Time, v protocol.Version) (*coalescedPacket, error) {
	var initialHdr, handshakeHdr, zeroRTTHdr *wire.ExtendedHeader
	var initialPayload, handshakePayload, zeroRTTPayload, oneRTTPayload payload
	var oneRTTPacketNumber protocol.PacketNumber; var oneRTTPacketNumberLen protocol.PacketNumberLen
	initialSealer, err := p.cryptoSetup.GetInitialSealer(); if err != nil && err != handshake.ErrKeysDropped { return nil, err }
	var size protocol.ByteCount
	if initialSealer != nil {
		initialHdr, initialPayload = p.maybeGetCryptoPacket(maxSize-protocol.ByteCount(initialSealer.Overhead()), protocol.EncryptionInitial, now, false, onlyAck, true, v)
		if initialPayload.length > 0 { size += p.longHeaderPacketLength(initialHdr, initialPayload, v) + protocol.ByteCount(initialSealer.Overhead()) }
	}
	var handshakeSealer sealer
	if (onlyAck && size == 0) || (!onlyAck && size < maxSize-protocol.MinCoalescedPacketSize) {
		var errHandshake error; handshakeSealer, errHandshake = p.cryptoSetup.GetHandshakeSealer()
		if errHandshake != nil && errHandshake != handshake.ErrKeysDropped && errHandshake != handshake.ErrKeysNotYetAvailable { return nil, errHandshake }
		if handshakeSealer != nil {
			handshakeHdr, handshakePayload = p.maybeGetCryptoPacket(maxSize-size-protocol.ByteCount(handshakeSealer.Overhead()), protocol.EncryptionHandshake, now, false, onlyAck, size == 0, v)
			if handshakePayload.length > 0 { s_ := p.longHeaderPacketLength(handshakeHdr, handshakePayload, v) + protocol.ByteCount(handshakeSealer.Overhead()); size += s_ }
		}
	}
	var zeroRTTSealer sealer; var oneRTTSealer handshake.ShortHeaderSealer
	var destConnIDFor1RTT protocol.ConnectionID; var keyPhaseFor1RTT protocol.KeyPhaseBit
	if (onlyAck && size == 0) || (!onlyAck && size < maxSize-protocol.MinCoalescedPacketSize) {
		var err1RTT error; oneRTTSealer, err1RTT = p.cryptoSetup.Get1RTTSealer()
		if err1RTT != nil && err1RTT != handshake.ErrKeysDropped && err1RTT != handshake.ErrKeysNotYetAvailable { return nil, err1RTT }
		if err1RTT == nil {
			keyPhaseFor1RTT = oneRTTSealer.KeyPhase(); destConnIDFor1RTT = p.getDestConnID()
			// PN for 1-RTT will be handled by appendShortHeaderPacket using pathID 0. Use main SPH for ECN.
			_, tempPnLen := p.pnManager.PeekPacketNumber(protocol.Encryption1RTT)
			hdrLen := wire.ShortHeaderLen(destConnIDFor1RTT, tempPnLen)
			oneRTTPayload = p.maybeGetShortHeaderPacket(oneRTTSealer, hdrLen, maxSize-size, onlyAck, size == 0, now, v, protocol.InitialPathID)
			if oneRTTPayload.length > 0 { size += p.shortHeaderPacketLength(destConnIDFor1RTT, tempPnLen, oneRTTPayload) + protocol.ByteCount(oneRTTSealer.Overhead()) }
		} else if p.perspective == protocol.PerspectiveClient && !onlyAck {
			var err0RTT error; zeroRTTSealer, err0RTT = p.cryptoSetup.Get0RTTSealer()
			if err0RTT != nil && err0RTT != handshake.ErrKeysDropped && err0RTT != handshake.ErrKeysNotYetAvailable { return nil, err0RTT }
			if zeroRTTSealer != nil {
				zeroRTTHdr, zeroRTTPayload = p.maybeGetAppDataPacketFor0RTT(zeroRTTSealer, maxSize-size, now, v)
				if zeroRTTPayload.length > 0 { size += p.longHeaderPacketLength(zeroRTTHdr, zeroRTTPayload, v) + protocol.ByteCount(zeroRTTSealer.Overhead()) }
			}
		}
	}
	if initialPayload.length == 0 && handshakePayload.length == 0 && zeroRTTPayload.length == 0 && oneRTTPayload.length == 0 { return nil, nil }
	buffer := getPacketBuffer()
	packet := &coalescedPacket{buffer: buffer, longHdrPackets: make([]*longHeaderPacket, 0, 3)}
	if initialPayload.length > 0 { /* ... append initial ... */
		padding := p.initialPaddingLen(initialPayload.frames, size, maxSize)
		cont, err := p.appendLongHeaderPacket(buffer, initialHdr, initialPayload, padding, protocol.EncryptionInitial, initialSealer, v)
		if err != nil { return nil, err }
		packet.longHdrPackets = append(packet.longHdrPackets, cont)
	}
	if handshakePayload.length > 0 { /* ... append handshake ... */
		cont, err := p.appendLongHeaderPacket(buffer, handshakeHdr, handshakePayload, 0, protocol.EncryptionHandshake, handshakeSealer, v)
		if err != nil { return nil, err }
		packet.longHdrPackets = append(packet.longHdrPackets, cont)
	}
	if zeroRTTPayload.length > 0 { /* ... append 0-RTT ... */
		longHdrPacket, err := p.appendLongHeaderPacket(buffer, zeroRTTHdr, zeroRTTPayload, 0, protocol.Encryption0RTT, zeroRTTSealer, v)
		if err != nil { return nil, err }
		packet.longHdrPackets = append(packet.longHdrPackets, longHdrPacket)
	} else if oneRTTPayload.length > 0 {
		ecn := p.sentPacketHandler.ECNMode(true) // Main SPH for coalesced 1-RTT ECN
		shp, err := p.appendShortHeaderPacket(buffer, destConnIDFor1RTT, oneRTTPacketNumber, oneRTTPacketNumberLen, keyPhaseFor1RTT, 0, oneRTTPayload, 0, maxSize, oneRTTSealer, false, ecn, v)
		if err != nil { return nil, err }
		packet.shortHdrPacket = &shp
	}
	return packet, nil
}

func (p *packetPacker) PackAckOnlyPacket(maxSize protocol.ByteCount, pathID protocol.PathID, destConnID protocol.ConnectionID, ecn protocol.ECN, now time.Time, v protocol.Version) (shortHeaderPacket, *packetBuffer, error) {
	buf := getPacketBuffer()
	packet, err := p.appendPacket(buf, true, maxSize, pathID, destConnID, ecn, now, v)
	return packet, buf, err
}

func (p *packetPacker) AppendPacket(buf *packetBuffer, maxPacketSize protocol.ByteCount, pathID protocol.PathID, destConnID protocol.ConnectionID, ecn protocol.ECN, now time.Time, v protocol.Version) (shortHeaderPacket, error) {
	return p.appendPacket(buf, false, maxPacketSize, pathID, destConnID, ecn, now, v)
}

func (p *packetPacker) appendPacket(
	buf *packetBuffer, onlyAck bool, maxPacketSize protocol.ByteCount,
	pathID protocol.PathID, destConnID protocol.ConnectionID, ecn protocol.ECN,
	now time.Time, v protocol.Version,
) (shortHeaderPacket, error) {
	sealer, err := p.cryptoSetup.Get1RTTSealer()
	if err != nil { return shortHeaderPacket{}, err }

	var currentPNLen protocol.PacketNumberLen
	var qPath quicPath
	if p.multiPathMgr != nil { qPath = p.multiPathMgr.GetPathForSending(pathID) }
	if qPath != nil && qPath.PacketNumberGenerator() != nil { _, currentPNLen = qPath.PacketNumberGenerator().Peek() } else { _, currentPNLen = p.pnManager.PeekPacketNumber(protocol.Encryption1RTT) }

	hdrLen := wire.ShortHeaderLen(destConnID, currentPNLen)
	pl := p.maybeGetShortHeaderPacket(sealer, hdrLen, maxPacketSize, onlyAck, true, now, v, pathID)
	if pl.length == 0 { return shortHeaderPacket{}, errNothingToPack }
	kp := sealer.KeyPhase()
	return p.appendShortHeaderPacket(buf, destConnID, 0, 0, kp, uint64(pathID), pl, 0, maxPacketSize, sealer, false, ecn, v)
}

func (p *packetPacker) maybeGetCryptoPacket(maxPacketSize protocol.ByteCount, encLevel protocol.EncryptionLevel, now time.Time, addPingIfEmpty bool, onlyAck, ackAllowed bool, v protocol.Version) (*wire.ExtendedHeader, payload) { /* ... */
	if onlyAck { if ack := p.acks.GetAckFrame(encLevel, now, true); ack != nil { return p.getLongHeader(encLevel, v), payload{ack:ack, length: ack.Length(v)}}; return nil, payload{}}
	var hasCryptoData func() bool; var popCryptoFrame func(maxLen protocol.ByteCount) *wire.CryptoFrame
	switch encLevel { case protocol.EncryptionInitial: hasCryptoData = p.initialStream.HasData; popCryptoFrame = p.initialStream.PopCryptoFrame; case protocol.EncryptionHandshake: hasCryptoData = p.handshakeStream.HasData; popCryptoFrame = p.handshakeStream.PopCryptoFrame }
	handler := p.retransmissionQueue.AckHandler(encLevel); hasRetransmission := p.retransmissionQueue.HasData(encLevel)
	var ack *wire.AckFrame; if ackAllowed { ack = p.acks.GetAckFrame(encLevel, now, !hasRetransmission && !hasCryptoData()) }
	var pl payload
	if !hasCryptoData() && !hasRetransmission && ack == nil { if !addPingIfEmpty { return nil, payload{} }; ping := &wire.PingFrame{}; pl.frames = append(pl.frames, ackhandler.Frame{Frame: ping, Handler: emptyHandler{}}); pl.length += ping.Length(v) }
	if ack != nil { pl.ack = ack; pl.length = ack.Length(v); maxPacketSize -= pl.length }
	hdr := p.getLongHeader(encLevel, v); maxPacketSize -= hdr.GetLength(v)
	if hasRetransmission { for { frame := p.retransmissionQueue.GetFrame(encLevel, maxPacketSize, v); if frame == nil { break }; pl.frames = append(pl.frames, ackhandler.Frame{ Frame: frame, Handler: p.retransmissionQueue.AckHandler(encLevel), }); frameLen := frame.Length(v); pl.length += frameLen; maxPacketSize -= frameLen }; return hdr, pl
	} else { for hasCryptoData() { cf := popCryptoFrame(maxPacketSize); if cf == nil { break }; pl.frames = append(pl.frames, ackhandler.Frame{Frame: cf, Handler: handler}); pl.length += cf.Length(v); maxPacketSize -= cf.Length(v) } }
	return hdr, pl
}
func (p *packetPacker) maybeGetAppDataPacketFor0RTT(sealer sealer, maxSize protocol.ByteCount, now time.Time, v protocol.Version) (*wire.ExtendedHeader, payload) { /* ... */
	if p.perspective != protocol.PerspectiveClient { return nil, payload{} }
	hdr := p.getLongHeader(protocol.Encryption0RTT, v); maxPayloadSize := maxSize - hdr.GetLength(v) - protocol.ByteCount(sealer.Overhead())
	return hdr, p.maybeGetAppDataPacket(maxPayloadSize, false, false, now, v, protocol.InitialPathID) // 0-RTT always on path 0
}
func (p *packetPacker) maybeGetShortHeaderPacket(sealer handshake.ShortHeaderSealer, hdrLen, maxPacketSize protocol.ByteCount, onlyAck, ackAllowed bool, now time.Time, v protocol.Version, pathIDForAck protocol.PathID) payload { /* ... */
	maxPayloadSize := maxPacketSize - hdrLen - protocol.ByteCount(sealer.Overhead())
	return p.maybeGetAppDataPacket(maxPayloadSize, onlyAck, ackAllowed, now, v, pathIDForAck)
}
func (p *packetPacker) maybeGetAppDataPacket(maxPayloadSize protocol.ByteCount, onlyAck, ackAllowed bool, now time.Time, v protocol.Version, pathIDForAck protocol.PathID) payload { /* ... */
	pl := p.composeNextPacket(maxPayloadSize, onlyAck, ackAllowed, now, v, pathIDForAck)
	if len(pl.frames) == 0 && len(pl.streamFrames) == 0 {
		if pl.ack == nil { // if no main ACK and no PATH_ACKs (implicit in pl.frames from composeNext)
			var hasPathAck bool
			for _, f := range pl.frames { if _, ok := f.Frame.(*wire.PathAckFrame); ok { hasPathAck = true; break } }
			if !hasPathAck { return payload{} }
		}
		if p.numNonAckElicitingAcks >= protocol.MaxNonAckElicitingAcks {
			ping := &wire.PingFrame{}; pl.frames = append(pl.frames, ackhandler.Frame{Frame: ping}); pl.length += ping.Length(v); p.numNonAckElicitingAcks = 0
		} else { p.numNonAckElicitingAcks++ }
	} else { p.numNonAckElicitingAcks = 0 }
	return pl
}
func (p *packetPacker) composeNextPacket(maxPayloadSize protocol.ByteCount, onlyAck, ackAllowed bool, now time.Time, v protocol.Version, pathIDForAck protocol.PathID) payload { /* ... */
	if onlyAck { // This means we *only* want an ACK, could be PATH_ACK or main ACK
		var pl payload
		var ecnForAck protocol.ECN = protocol.ECNUnsupported // Placeholder
		if p.multiPathMgr != nil {
			var pathToSendAckOn quicPath
			if pathIDForAck != protocol.InvalidPathID { // If a specific path is hinted for ACK
				pathToSendAckOn = p.multiPathMgr.GetPathForSending(pathIDForAck)
			}
			// Try to send PATH_ACK if specific path hinted and has ACK, or iterate if no hint
			if pathToSendAckOn != nil && pathToSendAckOn.ReceivedPacketHandler() != nil && pathToSendAckOn.ReceivedPacketHandler().HasAck() {
				ackData := pathToSendAckOn.ReceivedPacketHandler().GetAckFrame(now, true)
				if ackData != nil { /* ... create and add PathAckFrame to pl.frames ... */
					pathAck := &wire.PathAckFrame{PathIdentifier: pathToSendAckOn.ID(), LargestAcked: ackData.LargestAcked(), DelayTime: ackData.DelayTime, AckRanges: ackData.AckRanges, ECNCounts: &wire.ECNCounts{ECT0: ackData.ECT0, ECT1: ackData.ECT1, CE: ackData.ECNCE}};
					pathAck.AckRanges = make([]ackhandler.AckRange, len(ackData.AckRanges)); for i, r := range ackData.AckRanges { pathAck.AckRanges[i] = ackhandler.AckRange{Smallest: r.Smallest, Largest: r.Largest} }
					if pl.length+pathAck.Length(v) <= maxPayloadSize { pl.frames = append(pl.frames, ackhandler.Frame{Frame: pathAck, Handler: p.retransmissionQueue.AckHandler(protocol.Encryption1RTT)}); pl.length += pathAck.Length(v); return pl }
				}
			} else if pathIDForAck == protocol.InitialPathID { // Fallback to main ACK if path 0 hinted or no specific path PATH_ACK sent
				if ack := p.acks.GetAckFrame(protocol.Encryption1RTT, now, true); ack != nil { pl.ack = ack; pl.length += ack.Length(v); return pl }
			}
		} else { // No multiPathMgr, only main ACK
			if ack := p.acks.GetAckFrame(protocol.Encryption1RTT, now, true); ack != nil { return payload{ack: ack, length: ack.Length(v)} }
		}
		return payload{} // Nothing to send if onlyAck and no ACKs available
	}

	hasData := p.framer.HasData(); hasRetransmission := p.retransmissionQueue.HasData(protocol.Encryption1RTT)
	var hasAnyKindOfAck bool; var pl payload
	if p.multiPathMgr != nil { /* ... iterate paths for PATH_ACKs, update hasAnyKindOfAck ... */
		p.multiPathMgr.ForEachActivePath(func(pid protocol.PathID, rph ackhandler.ReceivedPacketHandler) bool {
			if rph.HasAck() {
				ackData := rph.GetAckFrame(now, false)
				if ackData != nil {
					pathAck := &wire.PathAckFrame{ PathIdentifier: pid, LargestAcked: ackData.LargestAcked(), DelayTime: ackData.DelayTime, AckRanges: ackData.AckRanges, ECNCounts: &wire.ECNCounts{ECT0: ackData.ECT0, ECT1: ackData.ECT1, CE: ackData.ECNCE}};
					pathAck.AckRanges = make([]ackhandler.AckRange, len(ackData.AckRanges)); for i, r := range ackData.AckRanges { pathAck.AckRanges[i] = ackhandler.AckRange{Smallest: r.Smallest, Largest: r.Largest} }
					if pl.length+pathAck.Length(v) <= maxPayloadSize { pl.frames = append(pl.frames, ackhandler.Frame{Frame: pathAck, Handler: p.retransmissionQueue.AckHandler(protocol.Encryption1RTT)}); pl.length += pathAck.Length(v); hasAnyKindOfAck = true; return true }
					return false
				}
			}
			return true
		})
	}
	if ackAllowed && !hasAnyKindOfAck { // Only add main ACK if no PATH_ACKs were added and it's allowed
		if ack := p.acks.GetAckFrame(protocol.Encryption1RTT, now, !hasRetransmission && !hasData); ack != nil {
			pl.ack = ack; pl.length += ack.Length(v); hasAnyKindOfAck = true
		}
	}
	if p.datagramQueue != nil { /* ... datagram logic ... */ }
	if hasAnyKindOfAck && !hasData && !hasRetransmission && len(pl.streamFrames) == 0 && countNonPathAckFrames(pl.frames) == 0 {
		if p.numNonAckElicitingAcks >= protocol.MaxNonAckElicitingAcks {
			ping := &wire.PingFrame{}; pl.frames = append(pl.frames, ackhandler.Frame{Frame: ping}); pl.length += ping.Length(v); p.numNonAckElicitingAcks = 0
		} else { p.numNonAckElicitingAcks++ }
	} else if len(pl.streamFrames) > 0 || countNonPathAckFrames(pl.frames) > 0 {
		p.numNonAckElicitingAcks = 0
	}
	if hasRetransmission { /* ... retransmission logic ... */ }
	if hasData { /* ... stream data logic ... */ }
	return pl
}
func countNonPathAckFrames(frames []ackhandler.Frame) int {
	count := 0
	for _, f := range frames { if _, ok := f.Frame.(*wire.PathAckFrame); !ok { count++ } }
	return count
}

func (p *packetPacker) PackPTOProbePacket(encLevel protocol.EncryptionLevel, maxPacketSize protocol.ByteCount, addPingIfEmpty bool, pathID protocol.PathID, destConnID protocol.ConnectionID, now time.Time, v protocol.Version) (*coalescedPacket, error) {
	if encLevel == protocol.Encryption1RTT {
		return p.packPTOProbePacket1RTT(maxPacketSize, addPingIfEmpty, pathID, destConnID, now, v)
	}
	var sealer handshake.LongHeaderSealer; switch encLevel { case protocol.EncryptionInitial: var err error; sealer, err = p.cryptoSetup.GetInitialSealer(); if err != nil { return nil, err } case protocol.EncryptionHandshake: var err error; sealer, err = p.cryptoSetup.GetHandshakeSealer(); if err != nil { return nil, err } default: panic("unknown enc level") }; hdr, pl := p.maybeGetCryptoPacket(maxPacketSize-protocol.ByteCount(sealer.Overhead()), encLevel, now, addPingIfEmpty, false, true, v); if pl.length == 0 { return nil, nil }; buffer := getPacketBuffer(); packet := &coalescedPacket{buffer: buffer}; size := p.longHeaderPacketLength(hdr, pl, v) + protocol.ByteCount(sealer.Overhead()); var padding protocol.ByteCount; if encLevel == protocol.EncryptionInitial { padding = p.initialPaddingLen(pl.frames, size, maxPacketSize) }; longHdrPacket, err := p.appendLongHeaderPacket(buffer, hdr, pl, padding, encLevel, sealer, v); if err != nil { return nil, err }; packet.longHdrPackets = []*longHeaderPacket{longHdrPacket}; return packet, nil
}

func (p *packetPacker) packPTOProbePacket1RTT(maxPacketSize protocol.ByteCount, addPingIfEmpty bool, pathID protocol.PathID, destConnID protocol.ConnectionID, now time.Time, v protocol.Version) (*coalescedPacket, error) {
	s, err := p.cryptoSetup.Get1RTTSealer(); if err != nil { return nil, err }
	kp := s.KeyPhase()
	var currentPNLen protocol.PacketNumberLen
	var qPath quicPath; if p.multiPathMgr != nil { qPath = p.multiPathMgr.GetPathForSending(pathID) }
	if qPath != nil && qPath.PacketNumberGenerator() != nil { _, currentPNLen = qPath.PacketNumberGenerator().Peek() } else { _, currentPNLen = p.pnManager.PeekPacketNumber(protocol.Encryption1RTT) }
	hdrLen := wire.ShortHeaderLen(destConnID, currentPNLen)
	// Pass pathID to maybeGetAppDataPacket for ACK decisions if needed
	pl := p.maybeGetAppDataPacket(maxPacketSize-protocol.ByteCount(s.Overhead())-hdrLen, false, true, now, v, pathID)
	if pl.length == 0 {
		if !addPingIfEmpty { return nil, nil }
		ping := &wire.PingFrame{}; pl.frames = append(pl.frames, ackhandler.Frame{Frame: ping, Handler: emptyHandler{}}); pl.length += ping.Length(v)
	}
	buffer := getPacketBuffer(); packet := &coalescedPacket{buffer: buffer}
	ecn := protocol.ECNUnsupported // Default ECN for PTO probe. Path specific SPH ECNMode could be used.
	if qPath != nil && qPath.SentPacketHandler() != nil { ecn = qPath.SentPacketHandler().ECNMode(true) } else { ecn = p.sentPacketHandler.ECNMode(true) }
	shp, err := p.appendShortHeaderPacket(buffer, destConnID, 0, 0, kp, uint64(pathID), pl, 0, maxPacketSize, s, false, ecn, v)
	if err != nil { return nil, err }
	packet.shortHdrPacket = &shp; return packet, nil
}

func (p *packetPacker) PackMTUProbePacket(ping ackhandler.Frame, size protocol.ByteCount, pathID protocol.PathID, destConnID protocol.ConnectionID, v protocol.Version) (shortHeaderPacket, *packetBuffer, error) {
	pl := payload{frames: []ackhandler.Frame{ping}, length: ping.Frame.Length(v)}
	buffer := getPacketBuffer(); s, err := p.cryptoSetup.Get1RTTSealer(); if err != nil { return shortHeaderPacket{}, nil, err }
	var currentPNLen protocol.PacketNumberLen
	var qPath quicPath; if p.multiPathMgr != nil { qPath = p.multiPathMgr.GetPathForSending(pathID) }
	if qPath != nil && qPath.PacketNumberGenerator() != nil { _, currentPNLen = qPath.PacketNumberGenerator().Peek() } else { _, currentPNLen = p.pnManager.PeekPacketNumber(protocol.Encryption1RTT) }
	padding := size - p.shortHeaderPacketLength(destConnID, currentPNLen, pl) - protocol.ByteCount(s.Overhead())
	kp := s.KeyPhase()
	ecn := protocol.ECNUnsupported // Default ECN for MTU probe.
	if qPath != nil && qPath.SentPacketHandler() != nil { ecn = qPath.SentPacketHandler().ECNMode(true) } else { ecn = p.sentPacketHandler.ECNMode(true) }
	packet, err := p.appendShortHeaderPacket(buffer, destConnID, 0, 0, kp, uint64(pathID), pl, padding, size, s, true, ecn, v)
	return packet, buffer, err
}

func (p *packetPacker) PackPathProbePacket(pathID protocol.PathID, packetDestConnID protocol.ConnectionID, frames []ackhandler.Frame, v protocol.Version) (shortHeaderPacket, *packetBuffer, error) {
	buf := getPacketBuffer(); s, err := p.cryptoSetup.Get1RTTSealer(); if err != nil { return shortHeaderPacket{}, nil, err }
	var l protocol.ByteCount; for _, f := range frames { l += f.Frame.Length(v) }
	payload := payload{frames: frames, length: l}
	var currentPNLen protocol.PacketNumberLen
	var qPath quicPath; if p.multiPathMgr != nil { qPath = p.multiPathMgr.GetPathForSending(pathID) }
	if qPath != nil && qPath.PacketNumberGenerator() != nil { _, currentPNLen = qPath.PacketNumberGenerator().Peek() } else { _, currentPNLen = p.pnManager.PeekPacketNumber(protocol.Encryption1RTT) }
	padding := protocol.MinInitialPacketSize - p.shortHeaderPacketLength(packetDestConnID, currentPNLen, payload) - protocol.ByteCount(s.Overhead())
	ecn := protocol.ECNUnsupported // Default ECN for Path probe.
	if qPath != nil && qPath.SentPacketHandler() != nil { ecn = qPath.SentPacketHandler().ECNMode(true) } else { ecn = p.sentPacketHandler.ECNMode(true) }
	packet, err := p.appendShortHeaderPacket(buf, packetDestConnID, 0, 0, s.KeyPhase(), uint64(pathID), payload, padding, protocol.MinInitialPacketSize, s, false, ecn, v)
	if err != nil { return shortHeaderPacket{}, nil, err }; packet.IsPathProbePacket = true; return packet, buf, err
}

func (p *packetPacker) getLongHeader(encLevel protocol.EncryptionLevel, v protocol.Version) *wire.ExtendedHeader { /* ... */
	pn, pnLen := p.pnManager.PeekPacketNumber(encLevel)
	hdr := &wire.ExtendedHeader{PacketNumber: pn, PacketNumberLen: pnLen, Version: v, SrcConnectionID: p.srcConnID, DestConnectionID: p.getDestConnID()}
	switch encLevel { case protocol.EncryptionInitial: hdr.Type = protocol.PacketTypeInitial; hdr.Token = p.token; case protocol.EncryptionHandshake: hdr.Type = protocol.PacketTypeHandshake; case protocol.Encryption0RTT: hdr.Type = protocol.PacketType0RTT }
	return hdr
}
func (p *packetPacker) appendLongHeaderPacket(buffer *packetBuffer, header *wire.ExtendedHeader, pl payload, padding protocol.ByteCount, encLevel protocol.EncryptionLevel, sealer sealer, v protocol.Version) (*longHeaderPacket, error) { /* ... */
	var paddingLen protocol.ByteCount; pnLen := protocol.ByteCount(header.PacketNumberLen); if pl.length < 4-pnLen { paddingLen = 4 - pnLen - pl.length }; paddingLen += padding
	header.Length = pnLen + protocol.ByteCount(sealer.Overhead()) + pl.length + paddingLen
	startLen := len(buffer.Data); raw := buffer.Data[startLen:]; var err error; raw, err = header.Append(raw, v); if err != nil { return nil, err }
	payloadOffset := protocol.ByteCount(len(raw)); raw, err = p.appendPacketPayload(raw, pl, paddingLen, v); if err != nil { return nil, err }
	raw = p.encryptPacket(raw, sealer, header.PacketNumber, payloadOffset, pnLen); buffer.Data = buffer.Data[:len(buffer.Data)+len(raw)]
	if pn := p.pnManager.PopPacketNumber(encLevel); pn != header.PacketNumber { return nil, fmt.Errorf("packetPacker BUG: Peeked and Popped packet numbers do not match: expected %d, got %d", pn, header.PacketNumber) }
	return &longHeaderPacket{header: header, ack: pl.ack, frames: pl.frames, streamFrames: pl.streamFrames, length: protocol.ByteCount(len(raw))}, nil
}

func (p *packetPacker) appendShortHeaderPacket(
	buffer *packetBuffer, destConnID protocol.ConnectionID,
	pnPlaceholder protocol.PacketNumber, pnLenPlaceholder protocol.PacketNumberLen,
	kp protocol.KeyPhaseBit, pathID uint64, pl payload, padding, maxPacketSize protocol.ByteCount,
	sealer handshake.ShortHeaderSealer, isMTUProbePacket bool, ecn protocol.ECN, v protocol.Version,
) (shortHeaderPacket, error) {
	var qPath quicPath; var actualPN protocol.PacketNumber; var actualPNLen protocol.PacketNumberLen
	if p.multiPathMgr != nil { qPath = p.multiPathMgr.GetPathForSending(protocol.PathID(pathID)) }
	if qPath != nil && qPath.PacketNumberGenerator() != nil {
		actualPN, actualPNLen = qPath.PacketNumberGenerator().Peek()
	} else {
		actualPN, actualPNLen = p.pnManager.PeekPacketNumber(protocol.Encryption1RTT)
	}

	var paddingLen protocol.ByteCount
	if pl.length < 4-protocol.ByteCount(actualPNLen) { paddingLen = 4 - protocol.ByteCount(actualPNLen) - pl.length }
	paddingLen += padding
	startLen := len(buffer.Data); raw := buffer.Data[startLen:]
	raw, err := wire.AppendShortHeader(raw, destConnID, actualPN, actualPNLen, kp)
	if err != nil { return shortHeaderPacket{}, err }
	payloadOffset := protocol.ByteCount(len(raw))
	raw, err = p.appendPacketPayload(raw, pl, paddingLen, v)
	if err != nil { return shortHeaderPacket{}, err }
	if !isMTUProbePacket {
		if size := protocol.ByteCount(len(raw) + sealer.Overhead()); size > maxPacketSize {
			return shortHeaderPacket{}, fmt.Errorf("PacketPacker BUG: packet too large (%d bytes, allowed %d bytes)", size, maxPacketSize)
		}
	}
	raw = p.encryptShortHeaderPacket(raw, sealer, actualPN, pathID, payloadOffset, protocol.ByteCount(actualPNLen))
	buffer.Data = buffer.Data[:len(buffer.Data)+len(raw)]

	if qPath != nil && qPath.PacketNumberGenerator() != nil {
		qPath.PacketNumberGenerator().Pop()
	} else {
		if poppedPN := p.pnManager.PopPacketNumber(protocol.Encryption1RTT); poppedPN != actualPN {
			return shortHeaderPacket{}, fmt.Errorf("packetPacker BUG: Popped main PN %d does not match peeked PN %d for path %d", poppedPN, actualPN, pathID)
		}
	}
	return shortHeaderPacket{
		PacketNumber: actualPN, PacketNumberLen: actualPNLen, KeyPhase: kp,
		StreamFrames: pl.streamFrames, Frames: pl.frames, Ack: pl.ack,
		Length: protocol.ByteCount(len(raw)), DestConnID: destConnID, IsPathMTUProbePacket: isMTUProbePacket,
	}, nil
}

func (p *packetPacker) appendPacketPayload(raw []byte, pl payload, paddingLen protocol.ByteCount, v protocol.Version) ([]byte, error) { /* ... */
	payloadOffset := len(raw)
	if pl.ack != nil { var err error; raw, err = pl.ack.Append(raw, v); if err != nil { return nil, err } }
	if paddingLen > 0 { raw = append(raw, make([]byte, paddingLen)...) }
	if len(pl.frames) > 1 { p.rand.Shuffle(len(pl.frames), func(i, j int) { pl.frames[i], pl.frames[j] = pl.frames[j], pl.frames[i] }) }
	for _, f := range pl.frames { var err error; raw, err = f.Frame.Append(raw, v); if err != nil { return nil, err } }
	for _, f := range pl.streamFrames { var err error; raw, err = f.Frame.Append(raw, v); if err != nil { return nil, err } }
	if payloadSize := protocol.ByteCount(len(raw)-payloadOffset) - paddingLen; payloadSize != pl.length { return nil, fmt.Errorf("PacketPacker BUG: payload size inconsistent (expected %d, got %d bytes)", pl.length, payloadSize) }
	return raw, nil
}
func (p *packetPacker) encryptPacket(raw []byte, sealer sealer, pn protocol.PacketNumber, payloadOffset, pnLen protocol.ByteCount) []byte { /* ... */
	_ = sealer.Seal(raw[payloadOffset:payloadOffset], raw[payloadOffset:], pn, raw[:payloadOffset])
	raw = raw[:len(raw)+sealer.Overhead()]
	pnOffset := payloadOffset - pnLen
	sealer.EncryptHeader(raw[pnOffset+4:pnOffset+4+16], &raw[0], raw[pnOffset:payloadOffset])
	return raw
}
func (p *packetPacker) encryptShortHeaderPacket(raw []byte, sealer handshake.ShortHeaderSealer, pn protocol.PacketNumber, pathID uint64, payloadOffset, pnLen protocol.ByteCount) []byte { /* ... */
	_ = sealer.Seal(raw[payloadOffset:payloadOffset], raw[payloadOffset:], pn, pathID, raw[:payloadOffset])
	raw = raw[:len(raw)+sealer.Overhead()]
	pnOffset := payloadOffset - pnLen
	sealer.EncryptHeader(raw[pnOffset+4:pnOffset+4+16], &raw[0], raw[pnOffset:payloadOffset])
	return raw
}
func (p *packetPacker) SetToken(token []byte) { p.token = token }
type emptyHandler struct{}
var _ ackhandler.FrameHandler = emptyHandler{}
func (emptyHandler) OnAcked(wire.Frame) {}
func (emptyHandler) OnLost(wire.Frame)  {}

[end of packet_packer.go]
