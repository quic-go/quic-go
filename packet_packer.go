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
	// path is defined in connection.go, ensure it's accessible or rethink import if packer moves
)

var errNothingToPack = errors.New("nothing to pack")

type packer interface {
	PackCoalescedPacket(onlyAck bool, maxPacketSize protocol.ByteCount, now time.Time, v protocol.Version, currentPath *path) (*coalescedPacket, error)
	PackAckOnlyPacket(maxPacketSize protocol.ByteCount, now time.Time, v protocol.Version, currentPath *path) (shortHeaderPacket, *packetBuffer, error)
	AppendPacket(_ *packetBuffer, maxPacketSize protocol.ByteCount, now time.Time, v protocol.Version, currentPath *path) (shortHeaderPacket, error)
	PackPTOProbePacket(_ protocol.EncryptionLevel, _ protocol.ByteCount, addPingIfEmpty bool, now time.Time, v protocol.Version, currentPath *path) (*coalescedPacket, error)
	PackConnectionClose(*qerr.TransportError, protocol.ByteCount, protocol.Version, *path) (*coalescedPacket, error)
	PackApplicationClose(*qerr.ApplicationError, protocol.ByteCount, protocol.Version, *path) (*coalescedPacket, error)
	PackPathProbePacket(destConnID protocol.ConnectionID, frame ackhandler.Frame, v protocol.Version, currentPath *path) (shortHeaderPacket, *packetBuffer, error)
	PackMTUProbePacket(ping wire.PingFrame, size protocol.ByteCount, v protocol.Version, currentPath *path) (shortHeaderPacket, *packetBuffer, error)

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
}

type shortHeaderPacket struct {
	PacketNumber         protocol.PacketNumber
	Frames               []ackhandler.Frame
	StreamFrames         []ackhandler.StreamFrame
	Ack                  *wire.AckFrame
	Length               protocol.ByteCount
	IsPathMTUProbePacket bool
	IsPathProbePacket    bool

	// used for logging
	DestConnID      protocol.ConnectionID
	PacketNumberLen protocol.PacketNumberLen
	KeyPhase        protocol.KeyPhaseBit
}

func (p *shortHeaderPacket) IsAckEliciting() bool { return ackhandler.HasAckElicitingFrames(p.Frames) }

type coalescedPacket struct {
	buffer         *packetBuffer
	longHdrPackets []*longHeaderPacket
	shortHdrPacket *shortHeaderPacket
}

// IsOnlyShortHeaderPacket says if this packet only contains a short header packet (and no long header packets).
func (p *coalescedPacket) IsOnlyShortHeaderPacket() bool {
	return len(p.longHdrPackets) == 0 && p.shortHdrPacket != nil
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

type packetNumberManager interface {
	PeekPacketNumber(protocol.EncryptionLevel) (protocol.PacketNumber, protocol.PacketNumberLen)
	PopPacketNumber(protocol.EncryptionLevel) protocol.PacketNumber
}

type sealingManager interface {
	GetInitialSealer() (handshake.LongHeaderSealer, error)
	GetHandshakeSealer() (handshake.LongHeaderSealer, error)
	Get0RTTSealer() (handshake.LongHeaderSealer, error)
	Get1RTTSealer() (handshake.ShortHeaderSealer, error)
	EncryptionLevel() protocol.EncryptionLevel
	OneRTTPacketKeyAvailable() bool
	KeyPhase() protocol.KeyPhaseBit
	ConnectionState() handshake.ConnectionState
}

type frameSource interface {
	HasData() bool
	Append([]ackhandler.Frame, []ackhandler.StreamFrame, protocol.ByteCount, time.Time, protocol.Version) ([]ackhandler.Frame, []ackhandler.StreamFrame, protocol.ByteCount)
	HasDataForEncryptionLevel(protocol.EncryptionLevel) bool
}

type ackFrameSource interface {
	GetAckFrame(_ protocol.EncryptionLevel, now time.Time, onlyIfQueued bool) *wire.AckFrame
}

type packetPacker struct {
	srcConnID     protocol.ConnectionID
	getDestConnID func() protocol.ConnectionID

	perspective protocol.Perspective
	cryptoSetup sealingManager
	config      *Config

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
}

var _ packer = &packetPacker{}

func newPacketPacker(
	srcConnID protocol.ConnectionID,
	getDestConnID func() protocol.ConnectionID,
	initialStream *initialCryptoStream,
	handshakeStream *cryptoStream,
	packetNumberManager packetNumberManager,
	retransmissionQueue *retransmissionQueue,
	cryptoSetup sealingManager,
	framer frameSource,
	acks ackFrameSource,
	datagramQueue *datagramQueue,
	perspective protocol.Perspective,
	config *Config,
) *packetPacker {
	var b [16]byte
	_, _ = crand.Read(b[:])

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
		rand:                *rand.New(rand.NewPCG(binary.BigEndian.Uint64(b[:8]), binary.BigEndian.Uint64(b[8:]))),
		pnManager:           packetNumberManager,
		config:              config,
	}
}

func (p *packetPacker) PackConnectionClose(quicErr *qerr.TransportError, maxPacketSize protocol.ByteCount, v protocol.Version, currentPath *path) (*coalescedPacket, error) {
	var reasonPhrase string
	if p.config.EnableDetailedConnectionCloseFrames {
		reasonPhrase = quicErr.ErrorMessage
	}
	return p.packConnectionCloseImpl(false, uint64(quicErr.ErrorCode), quicErr.FrameType, reasonPhrase, maxPacketSize, v, currentPath)
}

func (p *packetPacker) PackApplicationClose(quicErr *qerr.ApplicationError, maxPacketSize protocol.ByteCount, v protocol.Version, currentPath *path) (*coalescedPacket, error) {
	var reasonPhrase string
	if p.config.EnableDetailedConnectionCloseFrames {
		reasonPhrase = quicErr.ErrorMessage
	}
	if currentPath == nil || currentPath.pnSpace == nil {
		return nil, errors.New("PackApplicationClose called with nil currentPath or pnSpace")
	}
	if !p.cryptoSetup.OneRTTPacketKeyAvailable() {
		return nil, errors.New("cannot send application close: 1-RTT keys not available")
	}
	return p.packConnectionCloseImpl(true, uint64(quicErr.ErrorCode), 0, reasonPhrase, maxPacketSize, v, currentPath)
}

func (p *packetPacker) packConnectionCloseImpl(
	isApplicationError bool,
	errorCode uint64,
	frameType uint64,
	reason string,
	maxPacketSize protocol.ByteCount,
	v protocol.Version,
	currentPath *path,
) (*coalescedPacket, error) {
	ccf := &wire.ConnectionCloseFrame{
		IsApplicationError: isApplicationError,
		ErrorCode:          errorCode,
		FrameType:          frameType,
		ReasonPhrase:       reason,
	}

	buffer := getPacketBuffer()
	var shp *shortHeaderPacket
	var lhp []*longHeaderPacket

	if p.cryptoSetup.OneRTTPacketKeyAvailable() && (p.perspective == protocol.PerspectiveClient || (p.perspective == protocol.PerspectiveServer && p.cryptoSetup.ConnectionState().HandshakeState == handshake.StateDone)) {
		if currentPath == nil || currentPath.pnSpace == nil {
			return nil, errors.New("packConnectionCloseImpl (1-RTT) called with nil currentPath or pnSpace")
		}
		sealer, err := p.cryptoSetup.Get1RTTSealer()
		if err != nil {
			return nil, err
		}
		pn, pnLen := currentPath.pnSpace.pnGen.PeekPacketNumber()
		hdr := &wire.ShortHeader{
			DestConnectionID: p.getDestConnID(),
			PacketNumber:     pn,
			PacketNumberLen:  pnLen,
			KeyPhase:         sealer.KeyPhase(),
		}
		payload := payload{frames: []ackhandler.Frame{{Frame: ccf}}, length: ccf.Length(v)}
		appendedPacket, err := p.appendShortHeaderPacket(buffer, hdr.DestConnectionID, hdr.PacketNumber, hdr.PacketNumberLen, hdr.KeyPhase, payload, 0, maxPacketSize, sealer, false, v)
		if err != nil {
			return nil, err
		}
		currentPath.pnSpace.pnGen.PopPacketNumber()
		shp = &appendedPacket
	} else {
		encLevel := p.cryptoSetup.EncryptionLevel()
		if isApplicationError && (encLevel == protocol.EncryptionInitial || encLevel == protocol.EncryptionHandshake) {
			ccf.IsApplicationError = false
			ccf.ErrorCode = uint64(qerr.ApplicationErrorErrorCode)
			ccf.ReasonPhrase = ""
		}
		sealer, err := p.getLongHeaderSealer(encLevel)
		if err != nil {
			return nil, err
		}
		hdr := p.getLongHeader(encLevel, v)
		payload := payload{frames: []ackhandler.Frame{{Frame: ccf}}, length: ccf.Length(v)}

		var currentTotalSize protocol.ByteCount
		if shp != nil { currentTotalSize += shp.Length }
		for _, lp := range lhp { currentTotalSize += lp.length }

		paddingLen := p.initialPaddingLen(payload.frames, currentTotalSize + p.longHeaderPacketLength(hdr, payload, v) + protocol.ByteCount(sealer.Overhead()), maxPacketSize)
		if encLevel != protocol.EncryptionInitial {
			paddingLen = 0
		}

		appendedPacket, err := p.appendLongHeaderPacket(buffer, hdr, payload, paddingLen, encLevel, sealer, v)
		if err != nil {
			return nil, err
		}
		lhp = append(lhp, appendedPacket)
	}

	return &coalescedPacket{
		buffer:         buffer,
		longHdrPackets: lhp,
		shortHdrPacket: shp,
	}, nil
}

func (p *packetPacker) getLongHeaderSealer(encLevel protocol.EncryptionLevel) (handshake.LongHeaderSealer, error) {
	switch encLevel {
	case protocol.EncryptionInitial:
		return p.cryptoSetup.GetInitialSealer()
	case protocol.EncryptionHandshake:
		return p.cryptoSetup.GetHandshakeSealer()
	case protocol.Encryption0RTT:
		return p.cryptoSetup.Get0RTTSealer()
	default:
		return nil, fmt.Errorf("no long header sealer for %s", encLevel)
	}
}


// longHeaderPacketLength calculates the length of a serialized long header packet.
// It takes into account that packets that have a tiny payload need to be padded,
// such that len(payload) + packet number len >= 4 + AEAD overhead
func (p *packetPacker) longHeaderPacketLength(hdr *wire.ExtendedHeader, pl payload, v protocol.Version) protocol.ByteCount {
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

func (p *packetPacker) maxShortHeaderPacketOverhead(hdr *wire.ShortHeader) protocol.ByteCount {
	// Assumes max PN length for overhead calculation, as actual PN length isn't known yet.
	return wire.ShortHeaderLen(hdr.DestConnectionID, protocol.PacketNumberLen4) + protocol.ByteCount(p.cryptoSetup.Overhead(protocol.Encryption1RTT))
}


// PackCoalescedPacket packs a new packet.
// It packs an Initial / Handshake if there is data to send in these packet number spaces.
// It should only be called before the handshake is confirmed.
func (p *packetPacker) PackCoalescedPacket(onlyAck bool, maxSize protocol.ByteCount, now time.Time, v protocol.Version, currentPath *path) (*coalescedPacket, error) {
	var (
		initialHdr, handshakeHdr, zeroRTTHdr                            *wire.ExtendedHeader
		initialPayload, handshakePayload, zeroRTTPayload, oneRTTPayload payload
	)
	// Try packing an Initial packet.
	initialSealer, err := p.cryptoSetup.GetInitialSealer()
	if err != nil && err != handshake.ErrKeysDropped {
		return nil, err
	}
	var currentSize protocol.ByteCount
	if initialSealer != nil {
		initialHdr, initialPayload = p.maybeGetCryptoPacket(
			maxSize-protocol.ByteCount(initialSealer.Overhead()),
			protocol.EncryptionInitial,
			now,
			false,
			onlyAck,
			true,
			v,
		)
		if initialPayload.length > 0 {
			currentSize += p.longHeaderPacketLength(initialHdr, initialPayload, v) + protocol.ByteCount(initialSealer.Overhead())
		}
	}

	// Add a Handshake packet.
	var handshakeSealer sealer
	if (onlyAck && currentSize == 0) || (!onlyAck && currentSize < maxSize-protocol.MinCoalescedPacketSize) {
		var err error
		handshakeSealer, err = p.cryptoSetup.GetHandshakeSealer()
		if err != nil && err != handshake.ErrKeysDropped && err != handshake.ErrKeysNotYetAvailable {
			return nil, err
		}
		if handshakeSealer != nil {
			handshakeHdr, handshakePayload = p.maybeGetCryptoPacket(
				maxSize-currentSize-protocol.ByteCount(handshakeSealer.Overhead()),
				protocol.EncryptionHandshake,
				now,
				false,
				onlyAck,
				currentSize == 0, // only add PING if this is the first packet
				v,
			)
			if handshakePayload.length > 0 {
				s := p.longHeaderPacketLength(handshakeHdr, handshakePayload, v) + protocol.ByteCount(handshakeSealer.Overhead())
				currentSize += s
			}
		}
	}

	// Add a 0-RTT / 1-RTT packet.
	var zeroRTTSealer sealer
	var oneRTTSealer handshake.ShortHeaderSealer
	var oneRTTPacketNumber protocol.PacketNumber
	var oneRTTPacketNumberLen protocol.PacketNumberLen
	var connID protocol.ConnectionID
	var kp protocol.KeyPhaseBit

	if (onlyAck && currentSize == 0) || (!onlyAck && currentSize < maxSize-protocol.MinCoalescedPacketSize) {
		var err error
		oneRTTSealer, err = p.cryptoSetup.Get1RTTSealer()
		if err != nil && err != handshake.ErrKeysDropped && err != handshake.ErrKeysNotYetAvailable {
			return nil, err
		}
		if err == nil { // 1-RTT
			if currentPath == nil || currentPath.pnSpace == nil {
				return nil, errors.New("PackCoalescedPacket: currentPath or pnSpace is nil for 1-RTT component")
			}
			kp = oneRTTSealer.KeyPhase()
			connID = p.getDestConnID()
			oneRTTPacketNumber, oneRTTPacketNumberLen = currentPath.pnSpace.pnGen.PeekPacketNumber()
			hdrLen := wire.ShortHeaderLen(connID, oneRTTPacketNumberLen)
			oneRTTPayload = p.maybeGetShortHeaderPacket(oneRTTSealer, hdrLen, maxSize-currentSize, onlyAck, currentSize == 0, now, v)
			if oneRTTPayload.length > 0 {
				currentSize += p.shortHeaderPacketLength(connID, oneRTTPacketNumberLen, oneRTTPayload) + protocol.ByteCount(oneRTTSealer.Overhead())
			}
		} else if p.perspective == protocol.PerspectiveClient && !onlyAck { // 0-RTT packets can't contain ACK frames
			var err error
			zeroRTTSealer, err = p.cryptoSetup.Get0RTTSealer()
			if err != nil && err != handshake.ErrKeysDropped && err != handshake.ErrKeysNotYetAvailable {
				return nil, err
			}
			if zeroRTTSealer != nil {
				zeroRTTHdr, zeroRTTPayload = p.maybeGetAppDataPacketFor0RTT(zeroRTTSealer, maxSize-currentSize, now, v)
				if zeroRTTPayload.length > 0 {
					currentSize += p.longHeaderPacketLength(zeroRTTHdr, zeroRTTPayload, v) + protocol.ByteCount(zeroRTTSealer.Overhead())
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
		padding := p.initialPaddingLen(initialPayload.frames, currentSize, maxSize)
		cont, errLHP := p.appendLongHeaderPacket(buffer, initialHdr, initialPayload, padding, protocol.EncryptionInitial, initialSealer, v)
		if errLHP != nil {
			return nil, errLHP
		}
		packet.longHdrPackets = append(packet.longHdrPackets, cont)
	}
	if handshakePayload.length > 0 {
		cont, errLHP := p.appendLongHeaderPacket(buffer, handshakeHdr, handshakePayload, 0, protocol.EncryptionHandshake, handshakeSealer, v)
		if errLHP != nil {
			return nil, errLHP
		}
		packet.longHdrPackets = append(packet.longHdrPackets, cont)
	}
	if zeroRTTPayload.length > 0 {
		longHdrPacket, errLHP := p.appendLongHeaderPacket(buffer, zeroRTTHdr, zeroRTTPayload, 0, protocol.Encryption0RTT, zeroRTTSealer, v)
		if errLHP != nil {
			return nil, errLHP
		}
		packet.longHdrPackets = append(packet.longHdrPackets, longHdrPacket)
	} else if oneRTTPayload.length > 0 {
		shp, errSHP := p.appendShortHeaderPacket(buffer, connID, oneRTTPacketNumber, oneRTTPacketNumberLen, kp, oneRTTPayload, 0, maxSize, oneRTTSealer, false, v)
		if errSHP != nil {
			return nil, errSHP
		}
		packet.shortHdrPacket = &shp
		currentPath.pnSpace.pnGen.PopPacketNumber() // Pop after successful append
	}
	return packet, nil
}

// PackAckOnlyPacket packs a packet containing only an ACK in the application data packet number space.
// It should be called after the handshake is confirmed.
func (p *packetPacker) PackAckOnlyPacket(maxSize protocol.ByteCount, now time.Time, v protocol.Version, currentPath *path) (shortHeaderPacket, *packetBuffer, error) {
	ack := p.acks.GetAckFrame(protocol.Encryption1RTT, now, true)
	if ack == nil {
		return shortHeaderPacket{}, nil, errNothingToPack
	}
	if currentPath == nil || currentPath.pnSpace == nil {
		// This should not happen for 1-RTT packets.
		return shortHeaderPacket{}, nil, errors.New("PackAckOnlyPacket called with nil currentPath or pnSpace for 1-RTT")
	}

	buf := getPacketBuffer()
	destConnID := p.getDestConnID()

	payloadFrames := []ackhandler.Frame{{Frame: ack}}
	payloadLength, err := p.framer.AppendControlFrames(buf, payloadFrames, maxSize-protocol.ByteCount(wire.ShortHeaderLen(destConnID, 0)), v)
	if err != nil {
		// either the ACK can't fit, or we don't have connection ID and PN length yet
		// (though for 1-RTT, PN length should be known via path's PN generator)
		return shortHeaderPacket{}, nil, err
	}
	if payloadLength == 0 {
		buf.Release()
		return shortHeaderPacket{}, nil, errNothingToPack
	}

	// Use path-specific packet number generator
	pn, pnLen := currentPath.pnSpace.pnGen.PeekPacketNumber()
	hdr := &wire.ShortHeader{
		DestConnectionID: destConnID,
		PacketNumber:     pn,
		PacketNumberLen:  pnLen,
	}
	hdrRaw, err := hdr.Append(buf.Data[:0], v)
	if err != nil {
		return shortHeaderPacket{}, nil, err
	}
	buf.Data = buf.Data[len(hdrRaw):]
	buf.Data = append(hdrRaw, buf.Data...)
	buf.EncryptionTarget = buf.Data[len(hdrRaw):]
	buf.SetHeader(&wire.ExtendedHeader{Header: *hdr,
		KeyPhase:         p.cryptoSetup.KeyPhase()})
	buf.PrependChainingKey(payloadLength, hdr.PacketNumber, hdr.KeyPhase)

	// Pop from path-specific packet number generator
	currentPath.pnSpace.pnGen.PopPacketNumber()
	return shortHeaderPacket{
		DestConnID:      hdr.DestConnectionID,
		PacketNumber:     hdr.PacketNumber,
		PacketNumberLen:  hdr.PacketNumberLen,
		KeyPhase:         hdr.KeyPhase,
		Ack:              ack,
		Frames:           []ackhandler.Frame{},
		Length:           protocol.ByteCount(len(buf.Data)),
	}, buf, nil
}

// AppendPacket packs a packet in the application data packet number space.
// It should be called after the handshake is confirmed.
func (p *packetPacker) AppendPacket(buf *packetBuffer, maxSize protocol.ByteCount, now time.Time, v protocol.Version, currentPath *path) (shortHeaderPacket, error) {
	if currentPath == nil || currentPath.pnSpace == nil {
		// This should not happen for 1-RTT packets.
		// Consider returning an error or panic if appropriate for development.
		return shortHeaderPacket{}, errors.New("AppendPacket called with nil currentPath or pnSpace for 1-RTT")
	}
	if p.perspective == protocol.PerspectiveServer && p.cryptoSetup.ConnectionState().HandshakeState != handshake.StateDone {
		return shortHeaderPacket{}, errNothingToPack
	}
	return p.appendPacket(buf, false, maxSize, now, v, currentPath)
}

func (p *packetPacker) appendPacket(
	buf *packetBuffer,
	onlyAck bool,
	maxPacketSize protocol.ByteCount,
	now time.Time,
	v protocol.Version,
	currentPath *path,
) (shortHeaderPacket, error) {
	sealer, err := p.cryptoSetup.Get1RTTSealer()
	if err != nil {
		return shortHeaderPacket{}, err
	}
	// Use path-specific packet number generator for 1-RTT packets
	pn, pnLen := currentPath.pnSpace.pnGen.PeekPacketNumber()
	connID := p.getDestConnID()
	hdrLen := wire.ShortHeaderLen(connID, pnLen)
	pl := p.maybeGetShortHeaderPacket(sealer, hdrLen, maxPacketSize, onlyAck, true, now, v)
	if pl.length == 0 {
		return shortHeaderPacket{}, errNothingToPack
	}
	kp := sealer.KeyPhase()

	shp, err := p.appendShortHeaderPacket(buf, connID, pn, pnLen, kp, pl, 0, maxPacketSize, sealer, false, v)
	if err != nil {
		return shortHeaderPacket{}, err
	}
	// Pop from path-specific packet number generator only after successful append
	currentPath.pnSpace.pnGen.PopPacketNumber()
	return shp, nil
}


func (p *packetPacker) maybeGetCryptoPacket(
	maxPacketSize protocol.ByteCount,
	encLevel protocol.EncryptionLevel,
	now time.Time,
	addPingIfEmpty bool,
	onlyAck, ackAllowed bool,
	v protocol.Version,
) (*wire.ExtendedHeader, payload) {
	if onlyAck {
		if ack := p.acks.GetAckFrame(encLevel, now, true); ack != nil {
			return p.getLongHeader(encLevel, v), payload{
				ack:    ack,
				length: ack.Length(v),
			}
		}
		return nil, payload{}
	}

	var hasCryptoData func() bool
	var popCryptoFrame func(maxLen protocol.ByteCount) *wire.CryptoFrame
	switch encLevel {
	case protocol.EncryptionInitial:
		hasCryptoData = p.initialStream.HasData
		popCryptoFrame = p.initialStream.PopCryptoFrame
	case protocol.EncryptionHandshake:
		hasCryptoData = p.handshakeStream.HasData
		popCryptoFrame = p.handshakeStream.PopCryptoFrame
	default: // Should not happen for crypto packets
		return nil, payload{}
	}
	handler := p.retransmissionQueue.AckHandler(encLevel)
	hasRetransmission := p.retransmissionQueue.HasData(encLevel)

	var ack *wire.AckFrame
	if ackAllowed {
		ack = p.acks.GetAckFrame(encLevel, now, !hasRetransmission && !hasCryptoData())
	}
	var pl payload
	if !hasCryptoData() && !hasRetransmission && ack == nil {
		if !addPingIfEmpty {
			return nil, payload{}
		}
		ping := &wire.PingFrame{}
		pl.frames = append(pl.frames, ackhandler.Frame{Frame: ping, Handler: emptyHandler{}})
		pl.length += ping.Length(v)
	}

	if ack != nil {
		pl.ack = ack
		pl.length = ack.Length(v)
		maxPacketSize -= pl.length
	}
	hdr := p.getLongHeader(encLevel, v)
	maxPacketSize -= hdr.GetLength(v)
	if hasRetransmission {
		for {
			frame := p.retransmissionQueue.GetFrame(encLevel, maxPacketSize, v)
			if frame == nil {
				break
			}
			pl.frames = append(pl.frames, ackhandler.Frame{
				Frame:   frame,
				Handler: p.retransmissionQueue.AckHandler(encLevel),
			})
			frameLen := frame.Length(v)
			pl.length += frameLen
			maxPacketSize -= frameLen
		}
		return hdr, pl
	}
	else {
		for hasCryptoData() {
			cf := popCryptoFrame(maxPacketSize)
			if cf == nil {
				break
			}
			pl.frames = append(pl.frames, ackhandler.Frame{Frame: cf, Handler: handler})
			pl.length += cf.Length(v)
			maxPacketSize -= cf.Length(v)
		}
	}
	return hdr, pl
}

func (p *packetPacker) maybeGetAppDataPacketFor0RTT(sealer sealer, maxSize protocol.ByteCount, now time.Time, v protocol.Version) (*wire.ExtendedHeader, payload) {
	if p.perspective != protocol.PerspectiveClient {
		return nil, payload{}
	}

	hdr := p.getLongHeader(protocol.Encryption0RTT, v)
	maxPayloadSize := maxSize - hdr.GetLength(v) - protocol.ByteCount(sealer.Overhead())
	return hdr, p.maybeGetAppDataPacket(maxPayloadSize, false, false, now, v)
}

func (p *packetPacker) maybeGetShortHeaderPacket(
	sealer handshake.ShortHeaderSealer,
	hdrLen, maxPacketSize protocol.ByteCount,
	onlyAck, ackAllowed bool,
	now time.Time,
	v protocol.Version,
) payload {
	maxPayloadSize := maxPacketSize - hdrLen - protocol.ByteCount(sealer.Overhead())
	return p.maybeGetAppDataPacket(maxPayloadSize, onlyAck, ackAllowed, now, v)
}

func (p *packetPacker) maybeGetAppDataPacket(
	maxPayloadSize protocol.ByteCount,
	onlyAck, ackAllowed bool,
	now time.Time,
	v protocol.Version,
) payload {
	pl := p.composeNextPacket(maxPayloadSize, onlyAck, ackAllowed, now, v)

	if len(pl.frames) == 0 && len(pl.streamFrames) == 0 {
		if pl.ack == nil {
			return payload{}
		}
		if p.numNonAckElicitingAcks >= protocol.MaxNonAckElicitingAcks {
			ping := &wire.PingFrame{}
			pl.frames = append(pl.frames, ackhandler.Frame{Frame: ping})
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

func (p *packetPacker) composeNextPacket(
	maxPayloadSize protocol.ByteCount,
	onlyAck, ackAllowed bool,
	now time.Time,
	v protocol.Version,
) payload {
	if onlyAck {
		if ack := p.acks.GetAckFrame(protocol.Encryption1RTT, now, true); ack != nil {
			return payload{ack: ack, length: ack.Length(v)}
		}
		return payload{}
	}

	hasData := p.framer.HasData()
	hasRetransmission := p.retransmissionQueue.HasData(protocol.Encryption1RTT)

	var hasAck bool
	var pl payload
	if ackAllowed {
		if ack := p.acks.GetAckFrame(protocol.Encryption1RTT, now, !hasRetransmission && !hasData); ack != nil {
			pl.ack = ack
			pl.length += ack.Length(v)
			hasAck = true
		}
	}

	if p.datagramQueue != nil {
		if f := p.datagramQueue.Peek(); f != nil {
			size := f.Length(v)
			if size <= maxPayloadSize-pl.length {
				pl.frames = append(pl.frames, ackhandler.Frame{Frame: f})
				pl.length += size
				p.datagramQueue.Pop()
			} else if !hasAck {
				p.datagramQueue.Pop()
			}
		}
	}

	if hasAck && !hasData && !hasRetransmission {
		return pl
	}

	if hasRetransmission {
		for {
			remainingLen := maxPayloadSize - pl.length
			if remainingLen < protocol.MinStreamFrameSize {
				break
			}
			f := p.retransmissionQueue.GetFrame(protocol.Encryption1RTT, remainingLen, v)
			if f == nil {
				break
			}
			pl.frames = append(pl.frames, ackhandler.Frame{Frame: f, Handler: p.retransmissionQueue.AckHandler(protocol.Encryption1RTT)})
			pl.length += f.Length(v)
		}
	}

	if hasData {
		var lengthAdded protocol.ByteCount
		startLen := len(pl.frames)
		pl.frames, pl.streamFrames, lengthAdded = p.framer.Append(pl.frames, pl.streamFrames, maxPayloadSize-pl.length, now, v)
		pl.length += lengthAdded
		for i := startLen; i < len(pl.frames); i++ {
			if pl.frames[i].Handler != nil {
				continue
			}
			switch pl.frames[i].Frame.(type) {
			case *wire.PathChallengeFrame, *wire.PathResponseFrame:
			default:
				pl.frames[i].Handler = p.retransmissionQueue.AckHandler(protocol.Encryption1RTT)
			}
		}
	}
	return pl
}

func (p *packetPacker) PackPTOProbePacket(
	encLevel protocol.EncryptionLevel,
	maxPacketSize protocol.ByteCount,
	addPingIfEmpty bool,
	now time.Time,
	v protocol.Version,
	currentPath *path, // Added currentPath
) (*coalescedPacket, error) {
	if encLevel == protocol.Encryption1RTT {
		if currentPath == nil || currentPath.pnSpace == nil {
			return nil, errors.New("PackPTOProbePacket (1-RTT) called with nil currentPath or pnSpace")
		}
		return p.packPTOProbePacket1RTT(maxPacketSize, addPingIfEmpty, now, v, currentPath)
	}

	var sealer handshake.LongHeaderSealer
	switch encLevel {
	case protocol.EncryptionInitial:
		var err error
		sealer, err = p.cryptoSetup.GetInitialSealer()
		if err != nil {
			return nil, err
		}
	case protocol.EncryptionHandshake:
		var err error
		sealer, err = p.cryptoSetup.GetHandshakeSealer()
		if err != nil {
			return nil, err
		}
	default:
		panic("unknown encryption level for PTO probe (long header)")
	}
	hdr, pl := p.maybeGetCryptoPacket(
		maxPacketSize-protocol.ByteCount(sealer.Overhead()),
		encLevel,
		now,
		addPingIfEmpty,
		false,
		true,
		v,
	)
	if pl.length == 0 {
		return nil, nil
	}
	buffer := getPacketBuffer()
	packet := &coalescedPacket{buffer: buffer}
	currentTotalSize := p.longHeaderPacketLength(hdr, pl, v) + protocol.ByteCount(sealer.Overhead())
	var padding protocol.ByteCount
	if encLevel == protocol.EncryptionInitial {
		padding = p.initialPaddingLen(pl.frames, currentTotalSize, maxPacketSize)
	}

	longHdrPacket, err := p.appendLongHeaderPacket(buffer, hdr, pl, padding, encLevel, sealer, v)
	if err != nil {
		return nil, err
	}
	packet.longHdrPackets = []*longHeaderPacket{longHdrPacket}
	return packet, nil
}

func (p *packetPacker) packPTOProbePacket1RTT(maxPacketSize protocol.ByteCount, addPingIfEmpty bool, now time.Time, v protocol.Version, currentPath *path) (*coalescedPacket, error) {
	s, err := p.cryptoSetup.Get1RTTSealer()
	if err != nil {
		return nil, err
	}
	kp := s.KeyPhase()
	connID := p.getDestConnID()

	pn, pnLen := currentPath.pnSpace.pnGen.PeekPacketNumber()
	hdrLen := wire.ShortHeaderLen(connID, pnLen)
	pl := p.maybeGetAppDataPacket(maxPacketSize-protocol.ByteCount(s.Overhead())-hdrLen, false, true, now, v)
	if pl.length == 0 {
		if !addPingIfEmpty {
			return nil, nil
		}
		ping := &wire.PingFrame{}
		pl.frames = append(pl.frames, ackhandler.Frame{Frame: ping, Handler: emptyHandler{}})
		pl.length += ping.Length(v)
	}
	buffer := getPacketBuffer()
	packet := &coalescedPacket{buffer: buffer}
	shp, err := p.appendShortHeaderPacket(buffer, connID, pn, pnLen, kp, pl, 0, maxPacketSize, s, false, v)
	if err != nil {
		return nil, err
	}
	packet.shortHdrPacket = &shp
	currentPath.pnSpace.pnGen.PopPacketNumber()
	return packet, nil
}

func (p *packetPacker) PackMTUProbePacket(ping wire.PingFrame, size protocol.ByteCount, v protocol.Version, currentPath *path) (shortHeaderPacket, *packetBuffer, error) {
	if currentPath == nil || currentPath.pnSpace == nil {
		return shortHeaderPacket{}, nil, errors.New("PackMTUProbePacket called with nil currentPath or pnSpace")
	}
	pl := payload{
		frames: []ackhandler.Frame{{Frame: &ping, Handler: emptyHandler{}}},
		length: ping.Length(v),
	}
	buffer := getPacketBuffer()
	s, err := p.cryptoSetup.Get1RTTSealer()
	if err != nil {
		return shortHeaderPacket{}, nil, err
	}
	connID := p.getDestConnID()
	pn, pnLen := currentPath.pnSpace.pnGen.PeekPacketNumber()
	padding := size - p.shortHeaderPacketLength(connID, pnLen, pl) - protocol.ByteCount(s.Overhead())
	kp := s.KeyPhase()

	packet, err := p.appendShortHeaderPacket(buffer, connID, pn, pnLen, kp, pl, padding, size, s, true, v)
	if err == nil {
		currentPath.pnSpace.pnGen.PopPacketNumber()
	}
	return packet, buffer, err
}

func (p *packetPacker) PackPathProbePacket(destConnID protocol.ConnectionID, frame ackhandler.Frame, v protocol.Version, currentPath *path) (shortHeaderPacket, *packetBuffer, error) {
	var pn protocol.PacketNumber
	var pnLen protocol.PacketNumberLen

	if currentPath != nil && currentPath.pnSpace != nil {
		pn, pnLen = currentPath.pnSpace.pnGen.PeekPacketNumber()
	} else { // Fallback for server-side PATH_CHALLENGE or if path context is otherwise unavailable
		pn, pnLen = p.pnManager.PeekPacketNumber(protocol.Encryption1RTT)
	}

	buf := getPacketBuffer()
	s, err := p.cryptoSetup.Get1RTTSealer()
	if err != nil {
		return shortHeaderPacket{}, nil, err
	}

	payloadFrames := []ackhandler.Frame{frame}
	var plLength protocol.ByteCount
	for _, f := range payloadFrames {
		plLength += f.Frame.Length(v)
	}
	payload := payload{
		frames: payloadFrames,
		length: plLength,
	}
	// Path Probes are padded to MinInitialPacketSize
	padding := protocol.MinInitialPacketSize - p.shortHeaderPacketLength(destConnID, pnLen, payload) - protocol.ByteCount(s.Overhead())
	if padding < 0 {
	    padding = 0
	}

	packet, err := p.appendShortHeaderPacket(buf, destConnID, pn, pnLen, s.KeyPhase(), payload, padding, protocol.MinInitialPacketSize, s, false, v)
	if err == nil {
		if currentPath != nil && currentPath.pnSpace != nil {
			currentPath.pnSpace.pnGen.PopPacketNumber()
		} else { // Fallback
			p.pnManager.PopPacketNumber(protocol.Encryption1RTT)
		}
	}
	packet.IsPathProbePacket = true
	return packet, buf, err
}


func (p *packetPacker) getLongHeader(encLevel protocol.EncryptionLevel, v protocol.Version) *wire.ExtendedHeader {
	pn, pnLen := p.pnManager.PeekPacketNumber(encLevel)
	hdr := &wire.ExtendedHeader{
		PacketNumber:    pn,
		PacketNumberLen: pnLen,
	}
	hdr.Version = v
	hdr.SrcConnectionID = p.srcConnID
	hdr.DestConnectionID = p.getDestConnID()

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

func (p *packetPacker) appendLongHeaderPacket(buffer *packetBuffer, header *wire.ExtendedHeader, pl payload, padding protocol.ByteCount, encLevel protocol.EncryptionLevel, sealer sealer, v protocol.Version) (*longHeaderPacket, error) {
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
		return nil, fmt.Errorf("packetPacker BUG: Peeked and Popped packet numbers do not match: expected %d, got %d for encLevel %s", header.PacketNumber, pn, encLevel)
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
	v protocol.Version,
) (shortHeaderPacket, error) {
	var paddingLen protocol.ByteCount
	if pl.length < 4-protocol.ByteCount(pnLen) {
		paddingLen = 4 - protocol.ByteCount(pnLen) - pl.length
	}
	paddingLen += padding

	startLen := len(buffer.Data)
	raw := buffer.Data[startLen:]
	raw, err := wire.AppendShortHeader(raw, connID, pn, pnLen, kp)
	if err != nil {
		return shortHeaderPacket{}, err
	}
	payloadOffset := protocol.ByteCount(len(raw))

	raw, err = p.appendPacketPayload(raw, pl, paddingLen, v)
	if err != nil {
		return shortHeaderPacket{}, err
	}
	if !isMTUProbePacket {
		if size := protocol.ByteCount(len(raw) + sealer.Overhead()); size > maxPacketSize {
			return shortHeaderPacket{}, fmt.Errorf("PacketPacker BUG: packet too large (%d bytes, allowed %d bytes)", size, maxPacketSize)
		}
	}
	raw = p.encryptPacket(raw, sealer, pn, payloadOffset, protocol.ByteCount(pnLen))
	buffer.Data = buffer.Data[:len(buffer.Data)+len(raw)]

	return shortHeaderPacket{
		PacketNumber:         pn,
		PacketNumberLen:      pnLen,
		KeyPhase:             kp,
		StreamFrames:         pl.streamFrames,
		Frames:               pl.frames,
		Ack:                  pl.ack,
		Length:               protocol.ByteCount(len(raw)),
		DestConnID:           connID,
		IsPathMTUProbePacket: isMTUProbePacket,
	}, nil
}

// appendPacketPayload serializes the payload of a packet into the raw byte slice.
// It modifies the order of payload.frames.
func (p *packetPacker) appendPacketPayload(raw []byte, pl payload, paddingLen protocol.ByteCount, v protocol.Version) ([]byte, error) {
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
	if len(pl.frames) > 1 {
		p.rand.Shuffle(len(pl.frames), func(i, j int) { pl.frames[i], pl.frames[j] = pl.frames[j], pl.frames[i] })
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
	pnOffset := payloadOffset - pnLen
	sealer.EncryptHeader(raw[pnOffset+4:pnOffset+4+16], &raw[0], raw[pnOffset:payloadOffset])
	return raw
}

func (p *packetPacker) SetToken(token []byte) {
	p.token = token
}

type emptyHandler struct{}

var _ ackhandler.FrameHandler = emptyHandler{}

func (emptyHandler) OnAcked(wire.Frame) {}
func (emptyHandler) OnLost(wire.Frame)  {}

[end of packet_packer.go]
