package quic

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/lucas-clemente/quic-go/internal/ackhandler"
	"github.com/lucas-clemente/quic-go/internal/handshake"
	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/utils"
	"github.com/lucas-clemente/quic-go/internal/wire"
)

type packer interface {
	PackPacket() (*coalescedPacket, error)
	PackAppDataPacket() (*packedPacket, error)
	MaybePackProbePacket(protocol.EncryptionLevel) (*packedPacket, error)
	MaybePackAckPacket(handshakeConfirmed bool) (*packedPacket, error)
	PackConnectionClose(*wire.ConnectionCloseFrame) (*packedPacket, error)

	HandleTransportParameters(*handshake.TransportParameters)
	SetToken([]byte)
}

type sealer interface {
	handshake.LongHeaderSealer
}

type payload struct {
	frames []ackhandler.Frame
	ack    *wire.AckFrame
	length protocol.ByteCount
}

type packedPacket struct {
	buffer *packetBuffer
	*packetContents
}

type packetContents struct {
	header *wire.ExtendedHeader
	ack    *wire.AckFrame
	frames []ackhandler.Frame

	length protocol.ByteCount
}

type coalescedPacket struct {
	buffer *packetBuffer

	packets []*packetContents
}

func (p *packetContents) EncryptionLevel() protocol.EncryptionLevel {
	if !p.header.IsLongHeader {
		return protocol.Encryption1RTT
	}
	switch p.header.Type {
	case protocol.PacketTypeInitial:
		return protocol.EncryptionInitial
	case protocol.PacketTypeHandshake:
		return protocol.EncryptionHandshake
	case protocol.PacketType0RTT:
		return protocol.Encryption0RTT
	default:
		return protocol.EncryptionUnspecified
	}
}

func (p *packetContents) IsAckEliciting() bool {
	return ackhandler.HasAckElicitingFrames(p.frames)
}

func (p *packetContents) ToAckHandlerPacket(now time.Time, q *retransmissionQueue) *ackhandler.Packet {
	largestAcked := protocol.InvalidPacketNumber
	if p.ack != nil {
		largestAcked = p.ack.LargestAcked()
	}
	encLevel := p.EncryptionLevel()
	for i := range p.frames {
		if p.frames[i].OnLost != nil {
			continue
		}
		switch encLevel {
		case protocol.EncryptionInitial:
			p.frames[i].OnLost = q.AddInitial
		case protocol.EncryptionHandshake:
			p.frames[i].OnLost = q.AddHandshake
		case protocol.Encryption1RTT:
			p.frames[i].OnLost = q.AddAppData
		}
	}
	return &ackhandler.Packet{
		PacketNumber:    p.header.PacketNumber,
		LargestAcked:    largestAcked,
		Frames:          p.frames,
		Length:          p.length,
		EncryptionLevel: encLevel,
		SendTime:        now,
	}
}

func getMaxPacketSize(addr net.Addr) protocol.ByteCount {
	maxSize := protocol.ByteCount(protocol.MinInitialPacketSize)
	// If this is not a UDP address, we don't know anything about the MTU.
	// Use the minimum size of an Initial packet as the max packet size.
	if udpAddr, ok := addr.(*net.UDPAddr); ok {
		// If ip is not an IPv4 address, To4 returns nil.
		// Note that there might be some corner cases, where this is not correct.
		// See https://stackoverflow.com/questions/22751035/golang-distinguish-ipv4-ipv6.
		if udpAddr.IP.To4() == nil {
			maxSize = protocol.MaxPacketSizeIPv6
		} else {
			maxSize = protocol.MaxPacketSizeIPv4
		}
	}
	return maxSize
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
	AppendStreamFrames([]ackhandler.Frame, protocol.ByteCount) ([]ackhandler.Frame, protocol.ByteCount)
	AppendControlFrames([]ackhandler.Frame, protocol.ByteCount) ([]ackhandler.Frame, protocol.ByteCount)
}

type ackFrameSource interface {
	GetAckFrame(protocol.EncryptionLevel) *wire.AckFrame
}

type packetPacker struct {
	srcConnID     protocol.ConnectionID
	getDestConnID func() protocol.ConnectionID

	perspective protocol.Perspective
	version     protocol.VersionNumber
	cryptoSetup sealingManager

	initialStream   cryptoStream
	handshakeStream cryptoStream

	token []byte

	pnManager           packetNumberManager
	framer              frameSource
	acks                ackFrameSource
	retransmissionQueue *retransmissionQueue

	maxPacketSize          protocol.ByteCount
	numNonAckElicitingAcks int
}

var _ packer = &packetPacker{}

func newPacketPacker(
	srcConnID protocol.ConnectionID,
	getDestConnID func() protocol.ConnectionID,
	initialStream cryptoStream,
	handshakeStream cryptoStream,
	packetNumberManager packetNumberManager,
	retransmissionQueue *retransmissionQueue,
	remoteAddr net.Addr, // only used for determining the max packet size
	cryptoSetup sealingManager,
	framer frameSource,
	acks ackFrameSource,
	perspective protocol.Perspective,
	version protocol.VersionNumber,
) *packetPacker {
	return &packetPacker{
		cryptoSetup:         cryptoSetup,
		getDestConnID:       getDestConnID,
		srcConnID:           srcConnID,
		initialStream:       initialStream,
		handshakeStream:     handshakeStream,
		retransmissionQueue: retransmissionQueue,
		perspective:         perspective,
		version:             version,
		framer:              framer,
		acks:                acks,
		pnManager:           packetNumberManager,
		maxPacketSize:       getMaxPacketSize(remoteAddr),
	}
}

// PackConnectionClose packs a packet that ONLY contains a ConnectionCloseFrame
func (p *packetPacker) PackConnectionClose(ccf *wire.ConnectionCloseFrame) (*packedPacket, error) {
	payload := payload{
		frames: []ackhandler.Frame{{Frame: ccf}},
		length: ccf.Length(p.version),
	}
	// send the CONNECTION_CLOSE frame with the highest available encryption level
	var err error
	var hdr *wire.ExtendedHeader
	var sealer sealer
	encLevel := protocol.Encryption1RTT
	s, err := p.cryptoSetup.Get1RTTSealer()
	if err != nil {
		encLevel = protocol.EncryptionHandshake
		sealer, err = p.cryptoSetup.GetHandshakeSealer()
		if err != nil {
			encLevel = protocol.EncryptionInitial
			sealer, err = p.cryptoSetup.GetInitialSealer()
			if err != nil {
				return nil, err
			}
			hdr = p.getLongHeader(protocol.EncryptionInitial)
		} else {
			hdr = p.getLongHeader(protocol.EncryptionHandshake)
		}
	} else {
		sealer = s
		hdr = p.getShortHeader(s.KeyPhase())
	}

	return p.writeSinglePacket(hdr, payload, encLevel, sealer)
}

func (p *packetPacker) MaybePackAckPacket(handshakeConfirmed bool) (*packedPacket, error) {
	var encLevel protocol.EncryptionLevel
	var ack *wire.AckFrame
	if !handshakeConfirmed {
		ack = p.acks.GetAckFrame(protocol.EncryptionInitial)
		if ack != nil {
			encLevel = protocol.EncryptionInitial
		} else {
			ack = p.acks.GetAckFrame(protocol.EncryptionHandshake)
			if ack != nil {
				encLevel = protocol.EncryptionHandshake
			}
		}
	}
	if ack == nil {
		ack = p.acks.GetAckFrame(protocol.Encryption1RTT)
		if ack == nil {
			return nil, nil
		}
		encLevel = protocol.Encryption1RTT
	}
	if ack == nil {
		return nil, nil
	}
	payload := payload{
		ack:    ack,
		length: ack.Length(p.version),
	}

	sealer, hdr, err := p.getSealerAndHeader(encLevel)
	if err != nil {
		return nil, err
	}
	return p.writeSinglePacket(hdr, payload, encLevel, sealer)
}

// PackPacket packs a new packet.
// It packs an Initial / Handshake if there is data to send in these packet number spaces.
// It should only be called before the handshake is confirmed.
func (p *packetPacker) PackPacket() (*coalescedPacket, error) {
	buffer := getPacketBuffer()
	packet, err := p.packCoalescedPacket(buffer)
	if err != nil {
		return nil, err
	}

	if len(packet.packets) == 0 { // nothing to send
		buffer.Release()
		return nil, nil
	}
	return packet, nil
}

func (p *packetPacker) packCoalescedPacket(buffer *packetBuffer) (*coalescedPacket, error) {
	packet := &coalescedPacket{
		buffer:  buffer,
		packets: make([]*packetContents, 0, 3),
	}
	// Try packing an Initial packet.
	contents, err := p.maybeAppendInitialPacket(buffer)
	if err != nil && err != handshake.ErrKeysDropped {
		return nil, err
	}
	if contents != nil {
		packet.packets = append(packet.packets, contents)
	}
	if buffer.Len() >= p.maxPacketSize-protocol.MinCoalescedPacketSize {
		return packet, nil
	}

	// Add a Handshake packet.
	contents, err = p.maybeAppendHandshakePacket(buffer)
	if err != nil && err != handshake.ErrKeysDropped && err != handshake.ErrKeysNotYetAvailable {
		return nil, err
	}
	if contents != nil {
		packet.packets = append(packet.packets, contents)
	}
	if buffer.Len() >= p.maxPacketSize-protocol.MinCoalescedPacketSize {
		return packet, nil
	}

	// Add a 0-RTT / 1-RTT packet.
	contents, err = p.maybeAppendAppDataPacket(buffer)
	if err == handshake.ErrKeysNotYetAvailable {
		return packet, nil
	}
	if err != nil {
		return nil, err
	}
	if contents != nil {
		packet.packets = append(packet.packets, contents)
	}
	return packet, nil
}

// PackAppDataPacket packs a packet in the application data packet number space.
// It should be called after the handshake is confirmed.
func (p *packetPacker) PackAppDataPacket() (*packedPacket, error) {
	buffer := getPacketBuffer()
	contents, err := p.maybeAppendAppDataPacket(buffer)
	if err != nil || contents == nil {
		buffer.Release()
		return nil, err
	}
	return &packedPacket{
		buffer:         buffer,
		packetContents: contents,
	}, nil
}

func (p *packetPacker) maybeAppendInitialPacket(buffer *packetBuffer) (*packetContents, error) {
	sealer, err := p.cryptoSetup.GetInitialSealer()
	if err != nil {
		return nil, err
	}

	hasRetransmission := p.retransmissionQueue.HasInitialData()
	ack := p.acks.GetAckFrame(protocol.EncryptionInitial)
	if !p.initialStream.HasData() && !hasRetransmission && ack == nil {
		// nothing to send
		return nil, nil
	}
	return p.appendCryptoPacket(buffer, protocol.EncryptionInitial, sealer, ack, hasRetransmission)
}

func (p *packetPacker) maybeAppendHandshakePacket(buffer *packetBuffer) (*packetContents, error) {
	sealer, err := p.cryptoSetup.GetHandshakeSealer()
	if err != nil {
		return nil, err
	}

	hasRetransmission := p.retransmissionQueue.HasHandshakeData()
	// TODO: make sure that the ACK always fits
	ack := p.acks.GetAckFrame(protocol.EncryptionHandshake)
	if !p.handshakeStream.HasData() && !hasRetransmission && ack == nil {
		// nothing to send
		return nil, nil
	}
	return p.appendCryptoPacket(buffer, protocol.EncryptionHandshake, sealer, ack, hasRetransmission)
}

func (p *packetPacker) appendCryptoPacket(
	buffer *packetBuffer,
	encLevel protocol.EncryptionLevel,
	sealer handshake.LongHeaderSealer,
	ack *wire.AckFrame,
	hasRetransmission bool,
) (*packetContents, error) {
	s := p.handshakeStream
	maxPacketSize := p.maxPacketSize
	if encLevel == protocol.EncryptionInitial {
		s = p.initialStream
		if p.perspective == protocol.PerspectiveClient {
			maxPacketSize = protocol.MinInitialPacketSize
		}
	}
	remainingLen := maxPacketSize - buffer.Len() - protocol.ByteCount(sealer.Overhead())

	var payload payload
	if ack != nil {
		payload.ack = ack
		payload.length = ack.Length(p.version)
		remainingLen -= payload.length
	}
	hdr := p.getLongHeader(encLevel)
	remainingLen -= hdr.GetLength(p.version)
	if hasRetransmission {
		for {
			var f wire.Frame
			switch encLevel {
			case protocol.EncryptionInitial:
				f = p.retransmissionQueue.GetInitialFrame(remainingLen)
			case protocol.EncryptionHandshake:
				f = p.retransmissionQueue.GetHandshakeFrame(remainingLen)
			}
			if f == nil {
				break
			}
			payload.frames = append(payload.frames, ackhandler.Frame{Frame: f})
			frameLen := f.Length(p.version)
			payload.length += frameLen
			remainingLen -= frameLen
		}
	} else if s.HasData() {
		cf := s.PopCryptoFrame(remainingLen)
		payload.frames = []ackhandler.Frame{{Frame: cf}}
		payload.length += cf.Length(p.version)
	}
	return p.appendPacket(buffer, hdr, payload, encLevel, sealer)
}

func (p *packetPacker) maybeAppendAppDataPacket(buffer *packetBuffer) (*packetContents, error) {
	var sealer sealer
	var header *wire.ExtendedHeader
	var encLevel protocol.EncryptionLevel
	oneRTTSealer, err := p.cryptoSetup.Get1RTTSealer()
	if err == nil {
		encLevel = protocol.Encryption1RTT
		sealer = oneRTTSealer
		header = p.getShortHeader(oneRTTSealer.KeyPhase())
	} else {
		// 1-RTT sealer not yet available
		if p.perspective != protocol.PerspectiveClient {
			return nil, nil
		}
		sealer, err = p.cryptoSetup.Get0RTTSealer()
		if sealer == nil || err != nil {
			return nil, nil
		}
		encLevel = protocol.Encryption0RTT
		header = p.getLongHeader(protocol.Encryption0RTT)
	}
	headerLen := header.GetLength(p.version)

	maxSize := p.maxPacketSize - buffer.Len() - protocol.ByteCount(sealer.Overhead()) - headerLen
	payload := p.composeNextPacket(maxSize)

	// check if we have anything to send
	if len(payload.frames) == 0 && payload.ack == nil {
		return nil, nil
	}
	if len(payload.frames) == 0 { // the packet only contains an ACK
		if p.numNonAckElicitingAcks >= protocol.MaxNonAckElicitingAcks {
			ping := &wire.PingFrame{}
			payload.frames = append(payload.frames, ackhandler.Frame{Frame: ping})
			payload.length += ping.Length(p.version)
			p.numNonAckElicitingAcks = 0
		} else {
			p.numNonAckElicitingAcks++
		}
	} else {
		p.numNonAckElicitingAcks = 0
	}

	return p.appendPacket(buffer, header, payload, encLevel, sealer)
}

func (p *packetPacker) composeNextPacket(maxFrameSize protocol.ByteCount) payload {
	var payload payload

	// TODO: we don't need to request ACKs when sending 0-RTT packets
	if ack := p.acks.GetAckFrame(protocol.Encryption1RTT); ack != nil {
		payload.ack = ack
		payload.length += ack.Length(p.version)
	}

	for {
		remainingLen := maxFrameSize - payload.length
		if remainingLen < protocol.MinStreamFrameSize {
			break
		}
		f := p.retransmissionQueue.GetAppDataFrame(remainingLen)
		if f == nil {
			break
		}
		payload.frames = append(payload.frames, ackhandler.Frame{Frame: f})
		payload.length += f.Length(p.version)
	}

	var lengthAdded protocol.ByteCount
	payload.frames, lengthAdded = p.framer.AppendControlFrames(payload.frames, maxFrameSize-payload.length)
	payload.length += lengthAdded

	payload.frames, lengthAdded = p.framer.AppendStreamFrames(payload.frames, maxFrameSize-payload.length)
	payload.length += lengthAdded
	return payload
}

func (p *packetPacker) MaybePackProbePacket(encLevel protocol.EncryptionLevel) (*packedPacket, error) {
	var contents *packetContents
	var err error
	buffer := getPacketBuffer()
	switch encLevel {
	case protocol.EncryptionInitial:
		contents, err = p.maybeAppendInitialPacket(buffer)
	case protocol.EncryptionHandshake:
		contents, err = p.maybeAppendHandshakePacket(buffer)
	case protocol.Encryption1RTT:
		contents, err = p.maybeAppendAppDataPacket(buffer)
	default:
		panic("unknown encryption level")
	}
	if err != nil {
		return nil, err
	}
	return &packedPacket{
		buffer:         buffer,
		packetContents: contents,
	}, nil
}

func (p *packetPacker) getSealerAndHeader(encLevel protocol.EncryptionLevel) (sealer, *wire.ExtendedHeader, error) {
	switch encLevel {
	case protocol.EncryptionInitial:
		sealer, err := p.cryptoSetup.GetInitialSealer()
		if err != nil {
			return nil, nil, err
		}
		hdr := p.getLongHeader(protocol.EncryptionInitial)
		return sealer, hdr, nil
	case protocol.Encryption0RTT:
		sealer, err := p.cryptoSetup.Get0RTTSealer()
		if err != nil {
			return nil, nil, err
		}
		hdr := p.getLongHeader(protocol.Encryption0RTT)
		return sealer, hdr, nil
	case protocol.EncryptionHandshake:
		sealer, err := p.cryptoSetup.GetHandshakeSealer()
		if err != nil {
			return nil, nil, err
		}
		hdr := p.getLongHeader(protocol.EncryptionHandshake)
		return sealer, hdr, nil
	case protocol.Encryption1RTT:
		sealer, err := p.cryptoSetup.Get1RTTSealer()
		if err != nil {
			return nil, nil, err
		}
		hdr := p.getShortHeader(sealer.KeyPhase())
		return sealer, hdr, nil
	default:
		return nil, nil, fmt.Errorf("unexpected encryption level: %s", encLevel)
	}
}

func (p *packetPacker) getShortHeader(kp protocol.KeyPhaseBit) *wire.ExtendedHeader {
	pn, pnLen := p.pnManager.PeekPacketNumber(protocol.Encryption1RTT)
	hdr := &wire.ExtendedHeader{}
	hdr.PacketNumber = pn
	hdr.PacketNumberLen = pnLen
	hdr.DestConnectionID = p.getDestConnID()
	hdr.KeyPhase = kp
	return hdr
}

func (p *packetPacker) getLongHeader(encLevel protocol.EncryptionLevel) *wire.ExtendedHeader {
	pn, pnLen := p.pnManager.PeekPacketNumber(encLevel)
	hdr := &wire.ExtendedHeader{}
	hdr.IsLongHeader = true
	hdr.Version = p.version
	hdr.SrcConnectionID = p.srcConnID
	hdr.DestConnectionID = p.getDestConnID()

	// Set the length to the maximum packet size.
	// Since it is encoded as a varint, this guarantees us that the header will end up at most as big as GetLength() returns.
	hdr.Length = p.maxPacketSize

	hdr.PacketNumber = pn
	hdr.PacketNumberLen = pnLen
	if encLevel != protocol.Encryption0RTT {
		// Always send long header packets with the maximum packet number length.
		// This simplifies retransmissions: Since the header can't get any larger,
		// we don't need to split CRYPTO frames.
		hdr.PacketNumberLen = protocol.PacketNumberLen4
	}

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

// writeSinglePacket packs a single packet.
func (p *packetPacker) writeSinglePacket(
	header *wire.ExtendedHeader,
	payload payload,
	encLevel protocol.EncryptionLevel,
	sealer sealer,
) (*packedPacket, error) {
	buffer := getPacketBuffer()
	contents, err := p.appendPacket(buffer, header, payload, encLevel, sealer)
	if err != nil {
		return nil, err
	}
	return &packedPacket{
		buffer:         buffer,
		packetContents: contents,
	}, nil
}

func (p *packetPacker) appendPacket(
	buffer *packetBuffer,
	header *wire.ExtendedHeader,
	payload payload,
	encLevel protocol.EncryptionLevel,
	sealer sealer,
) (*packetContents, error) {
	var paddingLen protocol.ByteCount
	pnLen := protocol.ByteCount(header.PacketNumberLen)
	if encLevel != protocol.Encryption1RTT {
		if p.perspective == protocol.PerspectiveClient && header.Type == protocol.PacketTypeInitial {
			headerLen := header.GetLength(p.version)
			header.Length = pnLen + protocol.MinInitialPacketSize - headerLen
			paddingLen = protocol.ByteCount(protocol.MinInitialPacketSize-sealer.Overhead()) - headerLen - payload.length
		} else {
			header.Length = pnLen + protocol.ByteCount(sealer.Overhead()) + payload.length
		}
	} else if payload.length < 4-pnLen {
		paddingLen = 4 - pnLen - payload.length
	}

	hdrOffset := buffer.Len()
	buf := bytes.NewBuffer(buffer.Data)
	if err := header.Write(buf, p.version); err != nil {
		return nil, err
	}
	payloadOffset := buf.Len()

	if payload.ack != nil {
		if err := payload.ack.Write(buf, p.version); err != nil {
			return nil, err
		}
	}
	if paddingLen > 0 {
		buf.Write(bytes.Repeat([]byte{0}, int(paddingLen)))
	}
	for _, frame := range payload.frames {
		if err := frame.Write(buf, p.version); err != nil {
			return nil, err
		}
	}

	if payloadSize := protocol.ByteCount(buf.Len()-payloadOffset) - paddingLen; payloadSize != payload.length {
		return nil, fmt.Errorf("PacketPacker BUG: payload size inconsistent (expected %d, got %d bytes)", payload.length, payloadSize)
	}
	if size := protocol.ByteCount(buf.Len() + sealer.Overhead()); size > p.maxPacketSize {
		return nil, fmt.Errorf("PacketPacker BUG: packet too large (%d bytes, allowed %d bytes)", size, p.maxPacketSize)
	}

	raw := buffer.Data
	// encrypt the packet
	raw = raw[:buf.Len()]
	_ = sealer.Seal(raw[payloadOffset:payloadOffset], raw[payloadOffset:], header.PacketNumber, raw[hdrOffset:payloadOffset])
	raw = raw[0 : buf.Len()+sealer.Overhead()]
	// apply header protection
	pnOffset := payloadOffset - int(header.PacketNumberLen)
	sealer.EncryptHeader(raw[pnOffset+4:pnOffset+4+16], &raw[hdrOffset], raw[pnOffset:payloadOffset])
	buffer.Data = raw

	num := p.pnManager.PopPacketNumber(encLevel)
	if num != header.PacketNumber {
		return nil, errors.New("packetPacker BUG: Peeked and Popped packet numbers do not match")
	}
	return &packetContents{
		header: header,
		ack:    payload.ack,
		frames: payload.frames,
		length: buffer.Len() - hdrOffset,
	}, nil
}

func (p *packetPacker) SetToken(token []byte) {
	p.token = token
}

func (p *packetPacker) HandleTransportParameters(params *handshake.TransportParameters) {
	if params.MaxPacketSize != 0 {
		p.maxPacketSize = utils.MinByteCount(p.maxPacketSize, params.MaxPacketSize)
	}
}
