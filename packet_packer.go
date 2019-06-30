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
	MaybePackAckPacket() (*packedPacket, error)
	PackRetransmission(packet *ackhandler.Packet) ([]*packedPacket, error)
	PackConnectionClose(*wire.ConnectionCloseFrame) (*packedPacket, error)

	HandleTransportParameters(*handshake.TransportParameters)
	SetToken([]byte)
	ChangeDestConnectionID(protocol.ConnectionID)
}

type sealer interface {
	handshake.LongHeaderSealer
}

type payload struct {
	frames []wire.Frame
	ack    *wire.AckFrame
	length protocol.ByteCount
}

type packedPacket struct {
	header *wire.ExtendedHeader
	raw    []byte
	ack    *wire.AckFrame
	frames []wire.Frame

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

func (p *packedPacket) ToAckHandlerPacket() *ackhandler.Packet {
	return &ackhandler.Packet{
		PacketNumber:    p.header.PacketNumber,
		PacketType:      p.header.Type,
		Ack:             p.ack,
		Frames:          p.frames,
		Length:          protocol.ByteCount(len(p.raw)),
		EncryptionLevel: p.EncryptionLevel(),
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
	AppendStreamFrames([]wire.Frame, protocol.ByteCount) ([]wire.Frame, protocol.ByteCount)
	AppendControlFrames([]wire.Frame, protocol.ByteCount) ([]wire.Frame, protocol.ByteCount)
}

type ackFrameSource interface {
	GetAckFrame(protocol.EncryptionLevel) *wire.AckFrame
}

type packetPacker struct {
	destConnID protocol.ConnectionID
	srcConnID  protocol.ConnectionID

	perspective protocol.Perspective
	version     protocol.VersionNumber
	cryptoSetup sealingManager

	// Once the handshake is confirmed, we only need to send 1-RTT packets.
	handshakeConfirmed bool

	initialStream   cryptoStream
	handshakeStream cryptoStream

	token []byte

	pnManager packetNumberManager
	framer    frameSource
	acks      ackFrameSource

	maxPacketSize          protocol.ByteCount
	numNonAckElicitingAcks int
}

var _ packer = &packetPacker{}

func newPacketPacker(
	destConnID protocol.ConnectionID,
	srcConnID protocol.ConnectionID,
	initialStream cryptoStream,
	handshakeStream cryptoStream,
	packetNumberManager packetNumberManager,
	remoteAddr net.Addr, // only used for determining the max packet size
	cryptoSetup sealingManager,
	framer frameSource,
	acks ackFrameSource,
	perspective protocol.Perspective,
	version protocol.VersionNumber,
) *packetPacker {
	return &packetPacker{
		cryptoSetup:     cryptoSetup,
		destConnID:      destConnID,
		srcConnID:       srcConnID,
		initialStream:   initialStream,
		handshakeStream: handshakeStream,
		perspective:     perspective,
		version:         version,
		framer:          framer,
		acks:            acks,
		pnManager:       packetNumberManager,
		maxPacketSize:   getMaxPacketSize(remoteAddr),
	}
}

// PackConnectionClose packs a packet that ONLY contains a ConnectionCloseFrame
func (p *packetPacker) PackConnectionClose(ccf *wire.ConnectionCloseFrame) (*packedPacket, error) {
	payload := payload{
		frames: []wire.Frame{ccf},
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
	if !p.handshakeConfirmed {
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

// PackRetransmission packs a retransmission
// For packets sent after completion of the handshake, it might happen that 2 packets have to be sent.
// This can happen e.g. when a longer packet number is used in the header.
func (p *packetPacker) PackRetransmission(packet *ackhandler.Packet) ([]*packedPacket, error) {
	var controlFrames []wire.Frame
	var streamFrames []*wire.StreamFrame
	for _, f := range packet.Frames {
		// CRYPTO frames are treated as control frames here.
		// Since we're making sure that the header can never be larger for a retransmission,
		// we never have to split CRYPTO frames.
		if sf, ok := f.(*wire.StreamFrame); ok {
			sf.DataLenPresent = true
			streamFrames = append(streamFrames, sf)
		} else {
			controlFrames = append(controlFrames, f)
		}
	}

	var packets []*packedPacket
	for len(controlFrames) > 0 || len(streamFrames) > 0 {
		var frames []wire.Frame
		var length protocol.ByteCount

		sealer, hdr, err := p.getSealerAndHeader(packet.EncryptionLevel)
		if err != nil {
			return nil, err
		}

		hdrLen := hdr.GetLength(p.version)
		maxSize := p.maxPacketSize - protocol.ByteCount(sealer.Overhead()) - hdrLen

		for len(controlFrames) > 0 {
			frame := controlFrames[0]
			frameLen := frame.Length(p.version)
			if length+frameLen > maxSize {
				break
			}
			length += frameLen
			frames = append(frames, frame)
			controlFrames = controlFrames[1:]
		}

		for len(streamFrames) > 0 && length+protocol.MinStreamFrameSize < maxSize {
			frame := streamFrames[0]
			frame.DataLenPresent = false
			frameToAdd := frame

			sf, err := frame.MaybeSplitOffFrame(maxSize-length, p.version)
			if err != nil {
				return nil, err
			}
			if sf != nil {
				frameToAdd = sf
			} else {
				streamFrames = streamFrames[1:]
			}
			frame.DataLenPresent = true
			length += frameToAdd.Length(p.version)
			frames = append(frames, frameToAdd)
		}
		if sf, ok := frames[len(frames)-1].(*wire.StreamFrame); ok {
			sf.DataLenPresent = false
		}
		p, err := p.writeAndSealPacket(hdr, payload{frames: frames, length: length}, packet.EncryptionLevel, sealer)
		if err != nil {
			return nil, err
		}
		packets = append(packets, p)
	}
	return packets, nil
}

// PackPacket packs a new packet
// the other controlFrames are sent in the next packet, but might be queued and sent in the next packet if the packet would overflow MaxPacketSize otherwise
func (p *packetPacker) PackPacket() (*packedPacket, error) {
	if !p.handshakeConfirmed {
		packet, err := p.maybePackCryptoPacket()
		if err != nil {
			return nil, err
		}
		if packet != nil {
			return packet, nil
		}
	}

	sealer, err := p.cryptoSetup.Get1RTTSealer()
	if err != nil {
		// sealer not yet available
		return nil, nil
	}
	header := p.getShortHeader(sealer.KeyPhase())
	headerLen := header.GetLength(p.version)

	maxSize := p.maxPacketSize - protocol.ByteCount(sealer.Overhead()) - headerLen
	payload, err := p.composeNextPacket(maxSize)
	if err != nil {
		return nil, err
	}

	// check if we have anything to send
	if len(payload.frames) == 0 && payload.ack == nil {
		return nil, nil
	}
	if len(payload.frames) == 0 { // the packet only contains an ACK
		if p.numNonAckElicitingAcks >= protocol.MaxNonAckElicitingAcks {
			ping := &wire.PingFrame{}
			payload.frames = append(payload.frames, ping)
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

func (p *packetPacker) maybePackCryptoPacket() (*packedPacket, error) {
	var s cryptoStream
	var encLevel protocol.EncryptionLevel

	initialSealer, errInitialSealer := p.cryptoSetup.GetInitialSealer()
	handshakeSealer, errHandshakeSealer := p.cryptoSetup.GetHandshakeSealer()

	if errInitialSealer == handshake.ErrKeysDropped &&
		errHandshakeSealer == handshake.ErrKeysDropped {
		p.handshakeConfirmed = true
	}

	hasData := p.initialStream.HasData()
	ack := p.acks.GetAckFrame(protocol.EncryptionInitial)
	var sealer handshake.LongHeaderSealer
	if hasData || ack != nil {
		s = p.initialStream
		encLevel = protocol.EncryptionInitial
		sealer = initialSealer
		if errInitialSealer != nil {
			return nil, fmt.Errorf("PacketPacker BUG: no Initial sealer: %s", errInitialSealer)
		}
	} else {
		hasData = p.handshakeStream.HasData()
		ack = p.acks.GetAckFrame(protocol.EncryptionHandshake)
		if hasData || ack != nil {
			s = p.handshakeStream
			encLevel = protocol.EncryptionHandshake
			sealer = handshakeSealer
			if errHandshakeSealer != nil {
				return nil, fmt.Errorf("PacketPacker BUG: no Handshake sealer: %s", errHandshakeSealer)
			}
		}
	}
	if s == nil {
		return nil, nil
	}

	var payload payload
	if ack != nil {
		payload.ack = ack
		payload.length = ack.Length(p.version)
	}
	hdr := p.getLongHeader(encLevel)
	hdrLen := hdr.GetLength(p.version)
	if hasData {
		cf := s.PopCryptoFrame(p.maxPacketSize - hdrLen - protocol.ByteCount(sealer.Overhead()) - payload.length)
		payload.frames = []wire.Frame{cf}
		payload.length += cf.Length(p.version)
	}
	return p.writeAndSealPacket(hdr, payload, encLevel, sealer)
}

func (p *packetPacker) composeNextPacket(maxFrameSize protocol.ByteCount) (payload, error) {
	var payload payload

	if ack := p.acks.GetAckFrame(protocol.Encryption1RTT); ack != nil {
		payload.ack = ack
		payload.length += ack.Length(p.version)
	}

	frames, lengthAdded := p.framer.AppendControlFrames(payload.frames, maxFrameSize-payload.length)
	payload.length += lengthAdded

	frames, lengthAdded = p.framer.AppendStreamFrames(frames, maxFrameSize-payload.length)
	if len(frames) > 0 {
		payload.frames = append(payload.frames, frames...)
		payload.length += lengthAdded
	}
	return payload, nil
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
	hdr.DestConnectionID = p.destConnID
	hdr.KeyPhase = kp
	return hdr
}

func (p *packetPacker) getLongHeader(encLevel protocol.EncryptionLevel) *wire.ExtendedHeader {
	pn, pnLen := p.pnManager.PeekPacketNumber(encLevel)
	hdr := &wire.ExtendedHeader{}
	hdr.PacketNumber = pn
	hdr.PacketNumberLen = pnLen
	hdr.DestConnectionID = p.destConnID

	switch encLevel {
	case protocol.EncryptionInitial:
		hdr.Type = protocol.PacketTypeInitial
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
			header.Token = p.token
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

func (p *packetPacker) ChangeDestConnectionID(connID protocol.ConnectionID) {
	p.destConnID = connID
}

func (p *packetPacker) SetToken(token []byte) {
	p.token = token
}

func (p *packetPacker) HandleTransportParameters(params *handshake.TransportParameters) {
	if params.MaxPacketSize != 0 {
		p.maxPacketSize = utils.MinByteCount(p.maxPacketSize, params.MaxPacketSize)
	}
}
