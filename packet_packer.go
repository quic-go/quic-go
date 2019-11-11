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
	PackPacket() (*packedPacket, error)
	MaybePackProbePacket(protocol.EncryptionLevel) (*packedPacket, error)
	MaybePackAckPacket() (*packedPacket, error)
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
	header *wire.ExtendedHeader
	raw    []byte
	ack    *wire.AckFrame
	frames []ackhandler.Frame

	buffer *packetBuffer
}

func (p *packedPacket) EncryptionLevel() protocol.EncryptionLevel {
	if !p.header.IsLongHeader {
		return protocol.Encryption1RTT
	}
	switch p.header.Type {
	case protocol.PacketTypeInitial:
		return protocol.EncryptionInitial
	case protocol.PacketTypeHandshake:
		return protocol.EncryptionHandshake
	default:
		return protocol.EncryptionUnspecified
	}
}

func (p *packedPacket) IsAckEliciting() bool {
	return ackhandler.HasAckElicitingFrames(p.frames)
}

func (p *packedPacket) ToAckHandlerPacket(q *retransmissionQueue) *ackhandler.Packet {
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
		Length:          protocol.ByteCount(len(p.raw)),
		EncryptionLevel: encLevel,
		SendTime:        time.Now(),
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

	// Once both Initial and Handshake keys are dropped, we only send 1-RTT packets.
	droppedInitial   bool
	droppedHandshake bool

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

func (p *packetPacker) handshakeConfirmed() bool {
	return p.droppedInitial && p.droppedHandshake
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

	return p.writeAndSealPacket(hdr, payload, encLevel, sealer)
}

func (p *packetPacker) MaybePackAckPacket() (*packedPacket, error) {
	var encLevel protocol.EncryptionLevel
	var ack *wire.AckFrame
	if !p.handshakeConfirmed() {
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
	return p.writeAndSealPacket(hdr, payload, encLevel, sealer)
}

// PackPacket packs a new packet
// the other controlFrames are sent in the next packet, but might be queued and sent in the next packet if the packet would overflow MaxPacketSize otherwise
func (p *packetPacker) PackPacket() (*packedPacket, error) {
	if !p.handshakeConfirmed() {
		packet, err := p.maybePackCryptoPacket()
		if err != nil {
			return nil, err
		}
		if packet != nil {
			return packet, nil
		}
	}

	return p.maybePackAppDataPacket()
}

func (p *packetPacker) maybePackCryptoPacket() (*packedPacket, error) {
	// Try packing an Initial packet.
	packet, err := p.maybePackInitialPacket()
	if err == handshake.ErrKeysDropped {
		p.droppedInitial = true
	} else if err != nil || packet != nil {
		return packet, err
	}

	// No Initial was packed. Try packing a Handshake packet.
	packet, err = p.maybePackHandshakePacket()
	if err == handshake.ErrKeysDropped {
		p.droppedHandshake = true
		return nil, nil
	}
	if err == handshake.ErrKeysNotYetAvailable {
		return nil, nil
	}
	return packet, err
}

func (p *packetPacker) maybePackInitialPacket() (*packedPacket, error) {
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
	return p.packCryptoPacket(protocol.EncryptionInitial, sealer, ack, hasRetransmission)
}

func (p *packetPacker) maybePackHandshakePacket() (*packedPacket, error) {
	sealer, err := p.cryptoSetup.GetHandshakeSealer()

	if err != nil {
		return nil, err
	}

	hasRetransmission := p.retransmissionQueue.HasHandshakeData()
	ack := p.acks.GetAckFrame(protocol.EncryptionHandshake)
	if !p.handshakeStream.HasData() && !hasRetransmission && ack == nil {
		// nothing to send
		return nil, nil
	}
	return p.packCryptoPacket(protocol.EncryptionHandshake, sealer, ack, hasRetransmission)
}

func (p *packetPacker) packCryptoPacket(
	encLevel protocol.EncryptionLevel,
	sealer handshake.LongHeaderSealer,
	ack *wire.AckFrame,
	hasRetransmission bool,
) (*packedPacket, error) {
	s := p.initialStream
	if encLevel == protocol.EncryptionHandshake {
		s = p.handshakeStream
	}

	var payload payload
	if ack != nil {
		payload.ack = ack
		payload.length = ack.Length(p.version)
	}
	hdr := p.getLongHeader(encLevel)
	hdrLen := hdr.GetLength(p.version)
	if hasRetransmission {
		for {
			var f wire.Frame
			switch encLevel {
			case protocol.EncryptionInitial:
				remainingLen := protocol.MinInitialPacketSize - hdrLen - protocol.ByteCount(sealer.Overhead()) - payload.length
				f = p.retransmissionQueue.GetInitialFrame(remainingLen)
			case protocol.EncryptionHandshake:
				remainingLen := p.maxPacketSize - hdrLen - protocol.ByteCount(sealer.Overhead()) - payload.length
				f = p.retransmissionQueue.GetHandshakeFrame(remainingLen)
			}
			if f == nil {
				break
			}
			payload.frames = append(payload.frames, ackhandler.Frame{Frame: f})
			payload.length += f.Length(p.version)
		}
	} else if s.HasData() {
		cf := s.PopCryptoFrame(p.maxPacketSize - hdrLen - protocol.ByteCount(sealer.Overhead()) - payload.length)
		payload.frames = []ackhandler.Frame{{Frame: cf}}
		payload.length += cf.Length(p.version)
	}
	return p.writeAndSealPacket(hdr, payload, encLevel, sealer)
}

func (p *packetPacker) maybePackAppDataPacket() (*packedPacket, error) {
	sealer, err := p.cryptoSetup.Get1RTTSealer()
	if err != nil {
		// sealer not yet available
		return nil, nil
	}
	header := p.getShortHeader(sealer.KeyPhase())
	headerLen := header.GetLength(p.version)

	maxSize := p.maxPacketSize - protocol.ByteCount(sealer.Overhead()) - headerLen
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

	return p.writeAndSealPacket(header, payload, protocol.Encryption1RTT, sealer)
}

func (p *packetPacker) composeNextPacket(maxFrameSize protocol.ByteCount) payload {
	var payload payload

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
	switch encLevel {
	case protocol.EncryptionInitial:
		return p.maybePackInitialPacket()
	case protocol.EncryptionHandshake:
		return p.maybePackHandshakePacket()
	case protocol.Encryption1RTT:
		return p.maybePackAppDataPacket()
	default:
		panic("unknown encryption level")
	}
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
	hdr.PacketNumber = pn
	hdr.PacketNumberLen = pnLen
	hdr.DestConnectionID = p.getDestConnID()

	switch encLevel {
	case protocol.EncryptionInitial:
		hdr.Type = protocol.PacketTypeInitial
		hdr.Token = p.token
	case protocol.EncryptionHandshake:
		hdr.Type = protocol.PacketTypeHandshake
	}

	hdr.Version = p.version
	hdr.IsLongHeader = true
	// Always send Initial and Handshake packets with the maximum packet number length.
	// This simplifies retransmissions: Since the header can't get any larger,
	// we don't need to split CRYPTO frames.
	hdr.PacketNumberLen = protocol.PacketNumberLen4
	hdr.SrcConnectionID = p.srcConnID
	// Set the length to the maximum packet size.
	// Since it is encoded as a varint, this guarantees us that the header will end up at most as big as GetLength() returns.
	hdr.Length = p.maxPacketSize

	return hdr
}

func (p *packetPacker) writeAndSealPacket(
	header *wire.ExtendedHeader,
	payload payload,
	encLevel protocol.EncryptionLevel,
	sealer sealer,
) (*packedPacket, error) {
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
	return p.writeAndSealPacketWithPadding(header, payload, paddingLen, encLevel, sealer)
}

func (p *packetPacker) writeAndSealPacketWithPadding(
	header *wire.ExtendedHeader,
	payload payload,
	paddingLen protocol.ByteCount,
	encLevel protocol.EncryptionLevel,
	sealer sealer,
) (*packedPacket, error) {
	packetBuffer := getPacketBuffer()
	buffer := bytes.NewBuffer(packetBuffer.Slice[:0])

	if err := header.Write(buffer, p.version); err != nil {
		return nil, err
	}
	payloadOffset := buffer.Len()

	if payload.ack != nil {
		if err := payload.ack.Write(buffer, p.version); err != nil {
			return nil, err
		}
	}
	if paddingLen > 0 {
		buffer.Write(bytes.Repeat([]byte{0}, int(paddingLen)))
	}
	for _, frame := range payload.frames {
		if err := frame.Write(buffer, p.version); err != nil {
			return nil, err
		}
	}

	if payloadSize := protocol.ByteCount(buffer.Len()-payloadOffset) - paddingLen; payloadSize != payload.length {
		fmt.Printf("%#v\n", payload)
		return nil, fmt.Errorf("PacketPacker BUG: payload size inconsistent (expected %d, got %d bytes)", payload.length, payloadSize)
	}
	if size := protocol.ByteCount(buffer.Len() + sealer.Overhead()); size > p.maxPacketSize {
		return nil, fmt.Errorf("PacketPacker BUG: packet too large (%d bytes, allowed %d bytes)", size, p.maxPacketSize)
	}

	raw := buffer.Bytes()
	_ = sealer.Seal(raw[payloadOffset:payloadOffset], raw[payloadOffset:], header.PacketNumber, raw[:payloadOffset])
	raw = raw[0 : buffer.Len()+sealer.Overhead()]

	pnOffset := payloadOffset - int(header.PacketNumberLen)
	sealer.EncryptHeader(
		raw[pnOffset+4:pnOffset+4+16],
		&raw[0],
		raw[pnOffset:payloadOffset],
	)

	num := p.pnManager.PopPacketNumber(encLevel)
	if num != header.PacketNumber {
		return nil, errors.New("packetPacker BUG: Peeked and Popped packet numbers do not match")
	}
	return &packedPacket{
		header: header,
		raw:    raw,
		ack:    payload.ack,
		frames: payload.frames,
		buffer: packetBuffer,
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
