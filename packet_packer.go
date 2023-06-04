package quic

import (
	"errors"
	"fmt"
	"time"

	"github.com/quic-go/quic-go/internal/ackhandler"
	"github.com/quic-go/quic-go/internal/handshake"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/qerr"
	"github.com/quic-go/quic-go/internal/wire"
)

var errNothingToPack = errors.New("nothing to pack")

type packer interface {
	PackCoalescedPacket(onlyAck bool, maxPacketSize protocol.ByteCount, now time.Time, v protocol.VersionNumber) (*coalescedPacket, error)
	PackAckOnlyPacket(maxPacketSize protocol.ByteCount, now time.Time, v protocol.VersionNumber) (shortHeaderPacket, *packetBuffer, error)
	AppendPacket(buf *packetBuffer, maxPacketSize protocol.ByteCount, now time.Time, v protocol.VersionNumber) (shortHeaderPacket, error)
	MaybePackProbePacket(protocol.EncryptionLevel, protocol.ByteCount, time.Time, protocol.VersionNumber) (*coalescedPacket, error)
	PackConnectionClose(*qerr.TransportError, protocol.ByteCount, time.Time, protocol.VersionNumber) (*coalescedPacket, error)
	PackApplicationClose(*qerr.ApplicationError, protocol.ByteCount, time.Time, protocol.VersionNumber) (*coalescedPacket, error)
	PackMTUProbePacket(ping ackhandler.Frame, size protocol.ByteCount, now time.Time, v protocol.VersionNumber) (shortHeaderPacket, *packetBuffer, error)

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
	streamFrames []ackhandler.StreamFrame // only used for 0-RTT packets

	length protocol.ByteCount

	isMTUProbePacket bool
}

type shortHeaderPacket struct {
	*ackhandler.Packet
	// used for logging
	DestConnID      protocol.ConnectionID
	Ack             *wire.AckFrame
	PacketNumberLen protocol.PacketNumberLen
	KeyPhase        protocol.KeyPhaseBit
}

func (p *shortHeaderPacket) IsAckEliciting() bool { return ackhandler.HasAckElicitingFrames(p.Frames) }

type coalescedPacket struct {
	buffer         *packetBuffer
	longHdrPackets []*longHeaderPacket
	shortHdrPacket *shortHeaderPacket
}

func (p *longHeaderPacket) EncryptionLevel() protocol.EncryptionLevel {
	//nolint:exhaustive // Will never be called for Retry packets (and they don't have encrypted data).
	switch p.header.Type {
	case protocol.PacketTypeInitial:
		return protocol.EncryptionInitial
	case protocol.PacketTypeHandshake:
		return protocol.EncryptionHandshake
	case protocol.PacketType0RTT:
		return protocol.Encryption0RTT
	default:
		panic("can't determine encryption level")
	}
}

func (p *longHeaderPacket) IsAckEliciting() bool { return ackhandler.HasAckElicitingFrames(p.frames) }

func (p *longHeaderPacket) ToAckHandlerPacket(now time.Time, q *retransmissionQueue) *ackhandler.Packet {
	largestAcked := protocol.InvalidPacketNumber
	if p.ack != nil {
		largestAcked = p.ack.LargestAcked()
	}
	encLevel := p.EncryptionLevel()
	for i := range p.frames {
		if p.frames[i].OnLost != nil {
			continue
		}
		//nolint:exhaustive // Short header packets are handled separately.
		switch encLevel {
		case protocol.EncryptionInitial:
			p.frames[i].OnLost = q.AddInitial
		case protocol.EncryptionHandshake:
			p.frames[i].OnLost = q.AddHandshake
		case protocol.Encryption0RTT:
			p.frames[i].OnLost = q.AddAppData
		}
	}

	ap := ackhandler.GetPacket()
	ap.PacketNumber = p.header.PacketNumber
	ap.LargestAcked = largestAcked
	ap.Frames = p.frames
	ap.StreamFrames = p.streamFrames
	ap.Length = p.length
	ap.EncryptionLevel = encLevel
	ap.SendTime = now
	ap.IsPathMTUProbePacket = p.isMTUProbePacket
	return ap
}

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
	AppendStreamFrames([]ackhandler.StreamFrame, protocol.ByteCount, protocol.VersionNumber) ([]ackhandler.StreamFrame, protocol.ByteCount)
	AppendControlFrames([]ackhandler.Frame, protocol.ByteCount, protocol.VersionNumber) ([]ackhandler.Frame, protocol.ByteCount)
}

type ackFrameSource interface {
	GetAckFrame(encLevel protocol.EncryptionLevel, onlyIfQueued bool) *wire.AckFrame
}

type packetPacker struct {
	srcConnID     protocol.ConnectionID
	getDestConnID func() protocol.ConnectionID

	perspective protocol.Perspective
	cryptoSetup sealingManager

	initialStream   cryptoStream
	handshakeStream cryptoStream

	token []byte

	pnManager           packetNumberManager
	framer              frameSource
	acks                ackFrameSource
	datagramQueue       *datagramQueue
	retransmissionQueue *retransmissionQueue

	numNonAckElicitingAcks int
}

var _ packer = &packetPacker{}

func newPacketPacker(
	srcConnID protocol.ConnectionID,
	getDestConnID func() protocol.ConnectionID,
	initialStream, handshakeStream cryptoStream,
	packetNumberManager packetNumberManager,
	retransmissionQueue *retransmissionQueue,
	cryptoSetup sealingManager,
	framer frameSource,
	acks ackFrameSource,
	datagramQueue *datagramQueue,
	perspective protocol.Perspective,
) *packetPacker {
	return &packetPacker{
		cryptoSetup:         cryptoSetup,
		getDestConnID:       getDestConnID,
		srcConnID:           srcConnID,
		initialStream:       initialStream,
		handshakeStream:     handshakeStream,
		retransmissionQueue: retransmissionQueue,
		datagramQueue:       datagramQueue,
		perspective:         perspective,
		framer:              framer,
		acks:                acks,
		pnManager:           packetNumberManager,
	}
}

// PackConnectionClose packs a packet that closes the connection with a transport error.
func (p *packetPacker) PackConnectionClose(e *qerr.TransportError, maxPacketSize protocol.ByteCount, now time.Time, v protocol.VersionNumber) (*coalescedPacket, error) {
	var reason string
	// don't send details of crypto errors
	if !e.ErrorCode.IsCryptoError() {
		reason = e.ErrorMessage
	}
	return p.packConnectionClose(false, uint64(e.ErrorCode), e.FrameType, reason, maxPacketSize, now, v)
}

// PackApplicationClose packs a packet that closes the connection with an application error.
func (p *packetPacker) PackApplicationClose(e *qerr.ApplicationError, maxPacketSize protocol.ByteCount, now time.Time, v protocol.VersionNumber) (*coalescedPacket, error) {
	return p.packConnectionClose(true, uint64(e.ErrorCode), 0, e.ErrorMessage, maxPacketSize, now, v)
}

func (p *packetPacker) packConnectionClose(
	isApplicationError bool,
	errorCode uint64,
	frameType uint64,
	reason string,
	maxPacketSize protocol.ByteCount,
	now time.Time,
	v protocol.VersionNumber,
) (*coalescedPacket, error) {
	var sealers [4]sealer
	var hdrs [3]*wire.ExtendedHeader
	var payloads [4]payload
	var size protocol.ByteCount
	var connID protocol.ConnectionID
	var oneRTTPacketNumber protocol.PacketNumber
	var oneRTTPacketNumberLen protocol.PacketNumberLen
	var keyPhase protocol.KeyPhaseBit // only set for 1-RTT
	var numLongHdrPackets uint8
	encLevels := [4]protocol.EncryptionLevel{protocol.EncryptionInitial, protocol.EncryptionHandshake, protocol.Encryption0RTT, protocol.Encryption1RTT}
	for i, encLevel := range encLevels {
		if p.perspective == protocol.PerspectiveServer && encLevel == protocol.Encryption0RTT {
			continue
		}
		ccf := &wire.ConnectionCloseFrame{
			IsApplicationError: isApplicationError,
			ErrorCode:          errorCode,
			FrameType:          frameType,
			ReasonPhrase:       reason,
		}
		// don't send application errors in Initial or Handshake packets
		if isApplicationError && (encLevel == protocol.EncryptionInitial || encLevel == protocol.EncryptionHandshake) {
			ccf.IsApplicationError = false
			ccf.ErrorCode = uint64(qerr.ApplicationErrorErrorCode)
			ccf.ReasonPhrase = ""
		}
		pl := payload{
			frames: []ackhandler.Frame{{Frame: ccf}},
			length: ccf.Length(v),
		}

		var sealer sealer
		var err error
		switch encLevel {
		case protocol.EncryptionInitial:
			sealer, err = p.cryptoSetup.GetInitialSealer()
		case protocol.EncryptionHandshake:
			sealer, err = p.cryptoSetup.GetHandshakeSealer()
		case protocol.Encryption0RTT:
			sealer, err = p.cryptoSetup.Get0RTTSealer()
		case protocol.Encryption1RTT:
			var s handshake.ShortHeaderSealer
			s, err = p.cryptoSetup.Get1RTTSealer()
			if err == nil {
				keyPhase = s.KeyPhase()
			}
			sealer = s
		}
		if err == handshake.ErrKeysNotYetAvailable || err == handshake.ErrKeysDropped {
			continue
		}
		if err != nil {
			return nil, err
		}
		sealers[i] = sealer
		var hdr *wire.ExtendedHeader
		if encLevel == protocol.Encryption1RTT {
			connID = p.getDestConnID()
			oneRTTPacketNumber, oneRTTPacketNumberLen = p.pnManager.PeekPacketNumber(protocol.Encryption1RTT)
			size += p.shortHeaderPacketLength(connID, oneRTTPacketNumberLen, pl)
		} else {
			hdr = p.getLongHeader(encLevel, v)
			hdrs[i] = hdr
			size += p.longHeaderPacketLength(hdr, pl, v) + protocol.ByteCount(sealer.Overhead())
			numLongHdrPackets++
		}
		payloads[i] = pl
	}
	buffer := getPacketBuffer()
	packet := &coalescedPacket{
		buffer:         buffer,
		longHdrPackets: make([]*longHeaderPacket, 0, numLongHdrPackets),
	}
	for i, encLevel := range encLevels {
		if sealers[i] == nil {
			continue
		}
		var paddingLen protocol.ByteCount
		if encLevel == protocol.EncryptionInitial {
			paddingLen = p.initialPaddingLen(payloads[i].frames, size, maxPacketSize)
		}
		if encLevel == protocol.Encryption1RTT {
			ap, ack, err := p.appendShortHeaderPacket(buffer, connID, oneRTTPacketNumber, oneRTTPacketNumberLen, keyPhase, payloads[i], paddingLen, maxPacketSize, sealers[i], false, now, v)
			if err != nil {
				return nil, err
			}
			packet.shortHdrPacket = &shortHeaderPacket{
				Packet:          ap,
				DestConnID:      connID,
				Ack:             ack,
				PacketNumberLen: oneRTTPacketNumberLen,
				KeyPhase:        keyPhase,
			}
		} else {
			longHdrPacket, err := p.appendLongHeaderPacket(buffer, hdrs[i], payloads[i], paddingLen, encLevel, sealers[i], v)
			if err != nil {
				return nil, err
			}
			packet.longHdrPackets = append(packet.longHdrPackets, longHdrPacket)
		}
	}
	return packet, nil
}

// longHeaderPacketLength calculates the length of a serialized long header packet.
// It takes into account that packets that have a tiny payload need to be padded,
// such that len(payload) + packet number len >= 4 + AEAD overhead
func (p *packetPacker) longHeaderPacketLength(hdr *wire.ExtendedHeader, pl payload, v protocol.VersionNumber) protocol.ByteCount {
	var paddingLen protocol.ByteCount
	pnLen := protocol.ByteCount(hdr.PacketNumberLen)
	if pl.length < 4-pnLen {
		paddingLen = 4 - pnLen - pl.length
	}
	return hdr.GetLength(v) + pl.length + paddingLen
}

// shortHeaderPacketLength calculates the length of a serialized short header packet.
// It takes into account that packets that have a tiny payload need to be padded,
// such that len(payload) + packet number len >= 4 + AEAD overhead
func (p *packetPacker) shortHeaderPacketLength(connID protocol.ConnectionID, pnLen protocol.PacketNumberLen, pl payload) protocol.ByteCount {
	var paddingLen protocol.ByteCount
	if pl.length < 4-protocol.ByteCount(pnLen) {
		paddingLen = 4 - protocol.ByteCount(pnLen) - pl.length
	}
	return wire.ShortHeaderLen(connID, pnLen) + pl.length + paddingLen
}

// size is the expected size of the packet, if no padding was applied.
func (p *packetPacker) initialPaddingLen(frames []ackhandler.Frame, currentSize, maxPacketSize protocol.ByteCount) protocol.ByteCount {
	// For the server, only ack-eliciting Initial packets need to be padded.
	if p.perspective == protocol.PerspectiveServer && !ackhandler.HasAckElicitingFrames(frames) {
		return 0
	}
	if currentSize >= maxPacketSize {
		return 0
	}
	return maxPacketSize - currentSize
}

// PackCoalescedPacket packs a new packet.
// It packs an Initial / Handshake if there is data to send in these packet number spaces.
// It should only be called before the handshake is confirmed.
func (p *packetPacker) PackCoalescedPacket(onlyAck bool, maxPacketSize protocol.ByteCount, now time.Time, v protocol.VersionNumber) (*coalescedPacket, error) {
	var (
		initialHdr, handshakeHdr, zeroRTTHdr                            *wire.ExtendedHeader
		initialPayload, handshakePayload, zeroRTTPayload, oneRTTPayload payload
		oneRTTPacketNumber                                              protocol.PacketNumber
		oneRTTPacketNumberLen                                           protocol.PacketNumberLen
	)
	// Try packing an Initial packet.
	initialSealer, err := p.cryptoSetup.GetInitialSealer()
	if err != nil && err != handshake.ErrKeysDropped {
		return nil, err
	}
	var size protocol.ByteCount
	if initialSealer != nil {
		initialHdr, initialPayload = p.maybeGetCryptoPacket(maxPacketSize-protocol.ByteCount(initialSealer.Overhead()), protocol.EncryptionInitial, onlyAck, true, v)
		if initialPayload.length > 0 {
			size += p.longHeaderPacketLength(initialHdr, initialPayload, v) + protocol.ByteCount(initialSealer.Overhead())
		}
	}

	// Add a Handshake packet.
	var handshakeSealer sealer
	if (onlyAck && size == 0) || (!onlyAck && size < maxPacketSize-protocol.MinCoalescedPacketSize) {
		var err error
		handshakeSealer, err = p.cryptoSetup.GetHandshakeSealer()
		if err != nil && err != handshake.ErrKeysDropped && err != handshake.ErrKeysNotYetAvailable {
			return nil, err
		}
		if handshakeSealer != nil {
			handshakeHdr, handshakePayload = p.maybeGetCryptoPacket(maxPacketSize-size-protocol.ByteCount(handshakeSealer.Overhead()), protocol.EncryptionHandshake, onlyAck, size == 0, v)
			if handshakePayload.length > 0 {
				s := p.longHeaderPacketLength(handshakeHdr, handshakePayload, v) + protocol.ByteCount(handshakeSealer.Overhead())
				size += s
			}
		}
	}

	// Add a 0-RTT / 1-RTT packet.
	var zeroRTTSealer sealer
	var oneRTTSealer handshake.ShortHeaderSealer
	var connID protocol.ConnectionID
	var kp protocol.KeyPhaseBit
	if (onlyAck && size == 0) || (!onlyAck && size < maxPacketSize-protocol.MinCoalescedPacketSize) {
		var err error
		oneRTTSealer, err = p.cryptoSetup.Get1RTTSealer()
		if err != nil && err != handshake.ErrKeysDropped && err != handshake.ErrKeysNotYetAvailable {
			return nil, err
		}
		if err == nil { // 1-RTT
			kp = oneRTTSealer.KeyPhase()
			connID = p.getDestConnID()
			oneRTTPacketNumber, oneRTTPacketNumberLen = p.pnManager.PeekPacketNumber(protocol.Encryption1RTT)
			hdrLen := wire.ShortHeaderLen(connID, oneRTTPacketNumberLen)
			oneRTTPayload = p.maybeGetShortHeaderPacket(oneRTTSealer, hdrLen, maxPacketSize-size, onlyAck, size == 0, v)
			if oneRTTPayload.length > 0 {
				size += p.shortHeaderPacketLength(connID, oneRTTPacketNumberLen, oneRTTPayload) + protocol.ByteCount(oneRTTSealer.Overhead())
			}
		} else if p.perspective == protocol.PerspectiveClient && !onlyAck { // 0-RTT packets can't contain ACK frames
			var err error
			zeroRTTSealer, err = p.cryptoSetup.Get0RTTSealer()
			if err != nil && err != handshake.ErrKeysDropped && err != handshake.ErrKeysNotYetAvailable {
				return nil, err
			}
			if zeroRTTSealer != nil {
				zeroRTTHdr, zeroRTTPayload = p.maybeGetAppDataPacketFor0RTT(zeroRTTSealer, maxPacketSize-size, v)
				if zeroRTTPayload.length > 0 {
					size += p.longHeaderPacketLength(zeroRTTHdr, zeroRTTPayload, v) + protocol.ByteCount(zeroRTTSealer.Overhead())
				}
			}
		}
	}

	if initialPayload.length == 0 && handshakePayload.length == 0 && zeroRTTPayload.length == 0 && oneRTTPayload.length == 0 {
		return nil, nil
	}

	buffer := getPacketBuffer()
	packet := &coalescedPacket{
		buffer:         buffer,
		longHdrPackets: make([]*longHeaderPacket, 0, 3),
	}
	if initialPayload.length > 0 {
		padding := p.initialPaddingLen(initialPayload.frames, size, maxPacketSize)
		cont, err := p.appendLongHeaderPacket(buffer, initialHdr, initialPayload, padding, protocol.EncryptionInitial, initialSealer, v)
		if err != nil {
			return nil, err
		}
		packet.longHdrPackets = append(packet.longHdrPackets, cont)
	}
	if handshakePayload.length > 0 {
		cont, err := p.appendLongHeaderPacket(buffer, handshakeHdr, handshakePayload, 0, protocol.EncryptionHandshake, handshakeSealer, v)
		if err != nil {
			return nil, err
		}
		packet.longHdrPackets = append(packet.longHdrPackets, cont)
	}
	if zeroRTTPayload.length > 0 {
		longHdrPacket, err := p.appendLongHeaderPacket(buffer, zeroRTTHdr, zeroRTTPayload, 0, protocol.Encryption0RTT, zeroRTTSealer, v)
		if err != nil {
			return nil, err
		}
		packet.longHdrPackets = append(packet.longHdrPackets, longHdrPacket)
	} else if oneRTTPayload.length > 0 {
		ap, ack, err := p.appendShortHeaderPacket(buffer, connID, oneRTTPacketNumber, oneRTTPacketNumberLen, kp, oneRTTPayload, 0, maxPacketSize, oneRTTSealer, false, now, v)
		if err != nil {
			return nil, err
		}
		packet.shortHdrPacket = &shortHeaderPacket{
			Packet:          ap,
			DestConnID:      connID,
			Ack:             ack,
			PacketNumberLen: oneRTTPacketNumberLen,
			KeyPhase:        kp,
		}
	}
	return packet, nil
}

// PackAckOnlyPacket packs a packet containing only an ACK in the application data packet number space.
// It should be called after the handshake is confirmed.
func (p *packetPacker) PackAckOnlyPacket(maxPacketSize protocol.ByteCount, now time.Time, v protocol.VersionNumber) (shortHeaderPacket, *packetBuffer, error) {
	buf := getPacketBuffer()
	packet, err := p.appendPacket(buf, true, maxPacketSize, now, v)
	return packet, buf, err
}

// AppendPacket packs a packet in the application data packet number space.
// It should be called after the handshake is confirmed.
func (p *packetPacker) AppendPacket(buf *packetBuffer, maxPacketSize protocol.ByteCount, now time.Time, v protocol.VersionNumber) (shortHeaderPacket, error) {
	return p.appendPacket(buf, false, maxPacketSize, now, v)
}

func (p *packetPacker) appendPacket(buf *packetBuffer, onlyAck bool, maxPacketSize protocol.ByteCount, now time.Time, v protocol.VersionNumber) (shortHeaderPacket, error) {
	sealer, err := p.cryptoSetup.Get1RTTSealer()
	if err != nil {
		return shortHeaderPacket{}, err
	}
	pn, pnLen := p.pnManager.PeekPacketNumber(protocol.Encryption1RTT)
	connID := p.getDestConnID()
	hdrLen := wire.ShortHeaderLen(connID, pnLen)
	pl := p.maybeGetShortHeaderPacket(sealer, hdrLen, maxPacketSize, onlyAck, true, v)
	if pl.length == 0 {
		return shortHeaderPacket{}, errNothingToPack
	}
	kp := sealer.KeyPhase()

	ap, ack, err := p.appendShortHeaderPacket(buf, connID, pn, pnLen, kp, pl, 0, maxPacketSize, sealer, false, now, v)
	if err != nil {
		return shortHeaderPacket{}, err
	}
	return shortHeaderPacket{
		Packet:          ap,
		DestConnID:      connID,
		Ack:             ack,
		PacketNumberLen: pnLen,
		KeyPhase:        kp,
	}, nil
}

func (p *packetPacker) maybeGetCryptoPacket(maxPacketSize protocol.ByteCount, encLevel protocol.EncryptionLevel, onlyAck, ackAllowed bool, v protocol.VersionNumber) (*wire.ExtendedHeader, payload) {
	if onlyAck {
		if ack := p.acks.GetAckFrame(encLevel, true); ack != nil {
			return p.getLongHeader(encLevel, v), payload{
				ack:    ack,
				length: ack.Length(v),
			}
		}
		return nil, payload{}
	}

	var s cryptoStream
	var hasRetransmission bool
	//nolint:exhaustive // Initial and Handshake are the only two encryption levels here.
	switch encLevel {
	case protocol.EncryptionInitial:
		s = p.initialStream
		hasRetransmission = p.retransmissionQueue.HasInitialData()
	case protocol.EncryptionHandshake:
		s = p.handshakeStream
		hasRetransmission = p.retransmissionQueue.HasHandshakeData()
	}

	hasData := s.HasData()
	var ack *wire.AckFrame
	if ackAllowed {
		ack = p.acks.GetAckFrame(encLevel, !hasRetransmission && !hasData)
	}
	if !hasData && !hasRetransmission && ack == nil {
		// nothing to send
		return nil, payload{}
	}

	var pl payload
	if ack != nil {
		pl.ack = ack
		pl.length = ack.Length(v)
		maxPacketSize -= pl.length
	}
	hdr := p.getLongHeader(encLevel, v)
	maxPacketSize -= hdr.GetLength(v)
	if hasRetransmission {
		for {
			var f wire.Frame
			//nolint:exhaustive // 0-RTT packets can't contain any retransmission.s
			switch encLevel {
			case protocol.EncryptionInitial:
				f = p.retransmissionQueue.GetInitialFrame(maxPacketSize, v)
			case protocol.EncryptionHandshake:
				f = p.retransmissionQueue.GetHandshakeFrame(maxPacketSize, v)
			}
			if f == nil {
				break
			}
			pl.frames = append(pl.frames, ackhandler.Frame{Frame: f})
			frameLen := f.Length(v)
			pl.length += frameLen
			maxPacketSize -= frameLen
		}
	} else if s.HasData() {
		cf := s.PopCryptoFrame(maxPacketSize)
		pl.frames = []ackhandler.Frame{{Frame: cf}}
		pl.length += cf.Length(v)
	}
	return hdr, pl
}

func (p *packetPacker) maybeGetAppDataPacketFor0RTT(sealer sealer, maxPacketSize protocol.ByteCount, v protocol.VersionNumber) (*wire.ExtendedHeader, payload) {
	if p.perspective != protocol.PerspectiveClient {
		return nil, payload{}
	}

	hdr := p.getLongHeader(protocol.Encryption0RTT, v)
	maxPayloadSize := maxPacketSize - hdr.GetLength(v) - protocol.ByteCount(sealer.Overhead())
	return hdr, p.maybeGetAppDataPacket(maxPayloadSize, false, false, v)
}

func (p *packetPacker) maybeGetShortHeaderPacket(sealer handshake.ShortHeaderSealer, hdrLen protocol.ByteCount, maxPacketSize protocol.ByteCount, onlyAck, ackAllowed bool, v protocol.VersionNumber) payload {
	maxPayloadSize := maxPacketSize - hdrLen - protocol.ByteCount(sealer.Overhead())
	return p.maybeGetAppDataPacket(maxPayloadSize, onlyAck, ackAllowed, v)
}

func (p *packetPacker) maybeGetAppDataPacket(maxPayloadSize protocol.ByteCount, onlyAck, ackAllowed bool, v protocol.VersionNumber) payload {
	pl := p.composeNextPacket(maxPayloadSize, onlyAck, ackAllowed, v)

	// check if we have anything to send
	if len(pl.frames) == 0 && len(pl.streamFrames) == 0 {
		if pl.ack == nil {
			return payload{}
		}
		// the packet only contains an ACK
		if p.numNonAckElicitingAcks >= protocol.MaxNonAckElicitingAcks {
			ping := &wire.PingFrame{}
			pl.frames = append(pl.frames, ackhandler.Frame{
				Frame:  ping,
				OnLost: func(wire.Frame) {}, // don't retransmit the PING frame when it is lost
			})
			pl.length += ping.Length(v)
			p.numNonAckElicitingAcks = 0
		} else {
			p.numNonAckElicitingAcks++
		}
	} else {
		p.numNonAckElicitingAcks = 0
	}
	return pl
}

func (p *packetPacker) composeNextPacket(maxFrameSize protocol.ByteCount, onlyAck, ackAllowed bool, v protocol.VersionNumber) payload {
	if onlyAck {
		if ack := p.acks.GetAckFrame(protocol.Encryption1RTT, true); ack != nil {
			return payload{
				ack:    ack,
				length: ack.Length(v),
			}
		}
		return payload{}
	}

	pl := payload{streamFrames: make([]ackhandler.StreamFrame, 0, 1)}

	hasData := p.framer.HasData()
	hasRetransmission := p.retransmissionQueue.HasAppData()

	var hasAck bool
	if ackAllowed {
		if ack := p.acks.GetAckFrame(protocol.Encryption1RTT, !hasRetransmission && !hasData); ack != nil {
			pl.ack = ack
			pl.length += ack.Length(v)
			hasAck = true
		}
	}

	if p.datagramQueue != nil {
		if f := p.datagramQueue.Peek(); f != nil {
			size := f.Length(v)
			if size <= maxFrameSize-pl.length {
				pl.frames = append(pl.frames, ackhandler.Frame{
					Frame:  f,
					OnLost: func(wire.Frame) {}, // set it to a no-op. Then we won't set the default callback, which would retransmit the frame.
				})
				pl.length += size
				p.datagramQueue.Pop()
			}
		}
	}

	if hasAck && !hasData && !hasRetransmission {
		return pl
	}

	if hasRetransmission {
		for {
			remainingLen := maxFrameSize - pl.length
			if remainingLen < protocol.MinStreamFrameSize {
				break
			}
			f := p.retransmissionQueue.GetAppDataFrame(remainingLen, v)
			if f == nil {
				break
			}
			pl.frames = append(pl.frames, ackhandler.Frame{Frame: f})
			pl.length += f.Length(v)
		}
	}

	if hasData {
		var lengthAdded protocol.ByteCount
		pl.frames, lengthAdded = p.framer.AppendControlFrames(pl.frames, maxFrameSize-pl.length, v)
		pl.length += lengthAdded

		pl.streamFrames, lengthAdded = p.framer.AppendStreamFrames(pl.streamFrames, maxFrameSize-pl.length, v)
		pl.length += lengthAdded
	}
	return pl
}

func (p *packetPacker) MaybePackProbePacket(encLevel protocol.EncryptionLevel, maxPacketSize protocol.ByteCount, now time.Time, v protocol.VersionNumber) (*coalescedPacket, error) {
	if encLevel == protocol.Encryption1RTT {
		s, err := p.cryptoSetup.Get1RTTSealer()
		if err != nil {
			return nil, err
		}
		kp := s.KeyPhase()
		connID := p.getDestConnID()
		pn, pnLen := p.pnManager.PeekPacketNumber(protocol.Encryption1RTT)
		hdrLen := wire.ShortHeaderLen(connID, pnLen)
		pl := p.maybeGetAppDataPacket(maxPacketSize-protocol.ByteCount(s.Overhead())-hdrLen, false, true, v)
		if pl.length == 0 {
			return nil, nil
		}
		buffer := getPacketBuffer()
		packet := &coalescedPacket{buffer: buffer}
		ap, ack, err := p.appendShortHeaderPacket(buffer, connID, pn, pnLen, kp, pl, 0, maxPacketSize, s, false, now, v)
		if err != nil {
			return nil, err
		}
		packet.shortHdrPacket = &shortHeaderPacket{
			Packet:          ap,
			DestConnID:      connID,
			Ack:             ack,
			PacketNumberLen: pnLen,
			KeyPhase:        kp,
		}
		return packet, nil
	}

	var hdr *wire.ExtendedHeader
	var pl payload
	var sealer handshake.LongHeaderSealer
	//nolint:exhaustive // Probe packets are never sent for 0-RTT.
	switch encLevel {
	case protocol.EncryptionInitial:
		var err error
		sealer, err = p.cryptoSetup.GetInitialSealer()
		if err != nil {
			return nil, err
		}
		hdr, pl = p.maybeGetCryptoPacket(maxPacketSize-protocol.ByteCount(sealer.Overhead()), protocol.EncryptionInitial, false, true, v)
	case protocol.EncryptionHandshake:
		var err error
		sealer, err = p.cryptoSetup.GetHandshakeSealer()
		if err != nil {
			return nil, err
		}
		hdr, pl = p.maybeGetCryptoPacket(maxPacketSize-protocol.ByteCount(sealer.Overhead()), protocol.EncryptionHandshake, false, true, v)
	default:
		panic("unknown encryption level")
	}

	if pl.length == 0 {
		return nil, nil
	}
	buffer := getPacketBuffer()
	packet := &coalescedPacket{buffer: buffer}
	size := p.longHeaderPacketLength(hdr, pl, v) + protocol.ByteCount(sealer.Overhead())
	var padding protocol.ByteCount
	if encLevel == protocol.EncryptionInitial {
		padding = p.initialPaddingLen(pl.frames, size, maxPacketSize)
	}

	longHdrPacket, err := p.appendLongHeaderPacket(buffer, hdr, pl, padding, encLevel, sealer, v)
	if err != nil {
		return nil, err
	}
	packet.longHdrPackets = []*longHeaderPacket{longHdrPacket}
	return packet, nil
}

func (p *packetPacker) PackMTUProbePacket(ping ackhandler.Frame, size protocol.ByteCount, now time.Time, v protocol.VersionNumber) (shortHeaderPacket, *packetBuffer, error) {
	pl := payload{
		frames: []ackhandler.Frame{ping},
		length: ping.Frame.Length(v),
	}
	buffer := getPacketBuffer()
	s, err := p.cryptoSetup.Get1RTTSealer()
	if err != nil {
		return shortHeaderPacket{}, nil, err
	}
	connID := p.getDestConnID()
	pn, pnLen := p.pnManager.PeekPacketNumber(protocol.Encryption1RTT)
	padding := size - p.shortHeaderPacketLength(connID, pnLen, pl) - protocol.ByteCount(s.Overhead())
	kp := s.KeyPhase()
	ap, ack, err := p.appendShortHeaderPacket(buffer, connID, pn, pnLen, kp, pl, padding, size, s, true, now, v)
	if err != nil {
		return shortHeaderPacket{}, nil, err
	}
	return shortHeaderPacket{
		Packet:          ap,
		DestConnID:      connID,
		Ack:             ack,
		PacketNumberLen: pnLen,
		KeyPhase:        kp,
	}, buffer, nil
}

func (p *packetPacker) getLongHeader(encLevel protocol.EncryptionLevel, v protocol.VersionNumber) *wire.ExtendedHeader {
	pn, pnLen := p.pnManager.PeekPacketNumber(encLevel)
	hdr := &wire.ExtendedHeader{
		PacketNumber:    pn,
		PacketNumberLen: pnLen,
	}
	hdr.Version = v
	hdr.SrcConnectionID = p.srcConnID
	hdr.DestConnectionID = p.getDestConnID()

	//nolint:exhaustive // 1-RTT packets are not long header packets.
	switch encLevel {
	case protocol.EncryptionInitial:
		hdr.Type = protocol.PacketTypeInitial
		hdr.Token = p.token
	case protocol.EncryptionHandshake:
		hdr.Type = protocol.PacketTypeHandshake
	case protocol.Encryption0RTT:
		hdr.Type = protocol.PacketType0RTT
	}
	return hdr
}

func (p *packetPacker) appendLongHeaderPacket(buffer *packetBuffer, header *wire.ExtendedHeader, pl payload, padding protocol.ByteCount, encLevel protocol.EncryptionLevel, sealer sealer, v protocol.VersionNumber) (*longHeaderPacket, error) {
	var paddingLen protocol.ByteCount
	pnLen := protocol.ByteCount(header.PacketNumberLen)
	if pl.length < 4-pnLen {
		paddingLen = 4 - pnLen - pl.length
	}
	paddingLen += padding
	header.Length = pnLen + protocol.ByteCount(sealer.Overhead()) + pl.length + paddingLen

	startLen := len(buffer.Data)
	raw := buffer.Data[startLen:]
	raw, err := header.Append(raw, v)
	if err != nil {
		return nil, err
	}
	payloadOffset := protocol.ByteCount(len(raw))

	raw, err = p.appendPacketPayload(raw, pl, paddingLen, v)
	if err != nil {
		return nil, err
	}
	raw = p.encryptPacket(raw, sealer, header.PacketNumber, payloadOffset, pnLen)
	buffer.Data = buffer.Data[:len(buffer.Data)+len(raw)]

	if pn := p.pnManager.PopPacketNumber(encLevel); pn != header.PacketNumber {
		return nil, fmt.Errorf("packetPacker BUG: Peeked and Popped packet numbers do not match: expected %d, got %d", pn, header.PacketNumber)
	}
	return &longHeaderPacket{
		header:       header,
		ack:          pl.ack,
		frames:       pl.frames,
		streamFrames: pl.streamFrames,
		length:       protocol.ByteCount(len(raw)),
	}, nil
}

func (p *packetPacker) appendShortHeaderPacket(
	buffer *packetBuffer,
	connID protocol.ConnectionID,
	pn protocol.PacketNumber,
	pnLen protocol.PacketNumberLen,
	kp protocol.KeyPhaseBit,
	pl payload,
	padding, maxPacketSize protocol.ByteCount,
	sealer sealer,
	isMTUProbePacket bool,
	now time.Time,
	v protocol.VersionNumber,
) (*ackhandler.Packet, *wire.AckFrame, error) {
	var paddingLen protocol.ByteCount
	if pl.length < 4-protocol.ByteCount(pnLen) {
		paddingLen = 4 - protocol.ByteCount(pnLen) - pl.length
	}
	paddingLen += padding

	startLen := len(buffer.Data)
	raw := buffer.Data[startLen:]
	raw, err := wire.AppendShortHeader(raw, connID, pn, pnLen, kp)
	if err != nil {
		return nil, nil, err
	}
	payloadOffset := protocol.ByteCount(len(raw))

	raw, err = p.appendPacketPayload(raw, pl, paddingLen, v)
	if err != nil {
		return nil, nil, err
	}
	if !isMTUProbePacket {
		if size := protocol.ByteCount(len(raw) + sealer.Overhead()); size > maxPacketSize {
			return nil, nil, fmt.Errorf("PacketPacker BUG: packet too large (%d bytes, allowed %d bytes)", size, maxPacketSize)
		}
	}
	raw = p.encryptPacket(raw, sealer, pn, payloadOffset, protocol.ByteCount(pnLen))
	buffer.Data = buffer.Data[:len(buffer.Data)+len(raw)]

	// create the ackhandler.Packet
	largestAcked := protocol.InvalidPacketNumber
	if pl.ack != nil {
		largestAcked = pl.ack.LargestAcked()
	}
	for i := range pl.frames {
		if pl.frames[i].OnLost != nil {
			continue
		}
		pl.frames[i].OnLost = p.retransmissionQueue.AddAppData
	}

	ap := ackhandler.GetPacket()
	ap.PacketNumber = pn
	ap.LargestAcked = largestAcked
	ap.Frames = pl.frames
	ap.StreamFrames = pl.streamFrames
	ap.Length = protocol.ByteCount(len(raw))
	ap.EncryptionLevel = protocol.Encryption1RTT
	ap.SendTime = now
	ap.IsPathMTUProbePacket = isMTUProbePacket

	if newPN := p.pnManager.PopPacketNumber(protocol.Encryption1RTT); newPN != pn {
		return nil, nil, fmt.Errorf("packetPacker BUG: Peeked and Popped packet numbers do not match: expected %d, got %d", pn, newPN)
	}
	return ap, pl.ack, nil
}

func (p *packetPacker) appendPacketPayload(raw []byte, pl payload, paddingLen protocol.ByteCount, v protocol.VersionNumber) ([]byte, error) {
	payloadOffset := len(raw)
	if pl.ack != nil {
		var err error
		raw, err = pl.ack.Append(raw, v)
		if err != nil {
			return nil, err
		}
	}
	if paddingLen > 0 {
		raw = append(raw, make([]byte, paddingLen)...)
	}
	for _, f := range pl.frames {
		var err error
		raw, err = f.Frame.Append(raw, v)
		if err != nil {
			return nil, err
		}
	}
	for _, f := range pl.streamFrames {
		var err error
		raw, err = f.Frame.Append(raw, v)
		if err != nil {
			return nil, err
		}
	}

	if payloadSize := protocol.ByteCount(len(raw)-payloadOffset) - paddingLen; payloadSize != pl.length {
		return nil, fmt.Errorf("PacketPacker BUG: payload size inconsistent (expected %d, got %d bytes)", pl.length, payloadSize)
	}
	return raw, nil
}

func (p *packetPacker) encryptPacket(raw []byte, sealer sealer, pn protocol.PacketNumber, payloadOffset, pnLen protocol.ByteCount) []byte {
	_ = sealer.Seal(raw[payloadOffset:payloadOffset], raw[payloadOffset:], pn, raw[:payloadOffset])
	raw = raw[:len(raw)+sealer.Overhead()]
	// apply header protection
	pnOffset := payloadOffset - pnLen
	sealer.EncryptHeader(raw[pnOffset+4:pnOffset+4+16], &raw[0], raw[pnOffset:payloadOffset])
	return raw
}

func (p *packetPacker) SetToken(token []byte) {
	p.token = token
}
