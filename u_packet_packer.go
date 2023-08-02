package quic

import (
	"fmt"

	"github.com/quic-go/quic-go/internal/handshake"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/wire"
)

// uPacketPacker is an extended packetPacker which is used
// to customize some of the packetPacker's behaviors for
// UQUIC.
type uPacketPacker struct {
	*packetPacker

	// initPktNbrLen      PacketNumberLen
	// qfs                QUICFrames // [UQUIC] uses QUICFrames to customize encrypted frames
	// udpDatagramMinSize int
	uSpec *QUICSpec // [UQUIC]
}

func newUPacketPacker(
	packetPacker *packetPacker,
	uSpec *QUICSpec, // [UQUIC]
) *uPacketPacker {
	return &uPacketPacker{
		packetPacker: packetPacker,
		uSpec:        uSpec, // [UQUIC]
	}
}

// PackCoalescedPacket packs a new packet.
// It packs an Initial / Handshake if there is data to send in these packet number spaces.
// It should only be called before the handshake is confirmed.
func (p *uPacketPacker) PackCoalescedPacket(onlyAck bool, maxPacketSize protocol.ByteCount, v protocol.VersionNumber) (*coalescedPacket, error) {
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

		// // [UQUIC]
		// if len(initialPayload.frames) > 0 {
		// 	fmt.Printf("onlyAck: %t, PackCoalescedPacket: %v\n", onlyAck, initialPayload.frames[0].Frame)
		// }
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
		if onlyAck || len(initialPayload.frames) == 0 {
			// TODO: uQUIC should send Initial Packet if requested.
			// However, it should be otherwise configurable whether to request
			// to send Initial Packet or not. See quic-go#4007
			padding := p.initialPaddingLen(initialPayload.frames, size, maxPacketSize)
			cont, err := p.appendLongHeaderPacket(buffer, initialHdr, initialPayload, padding, protocol.EncryptionInitial, initialSealer, v)
			if err != nil {
				return nil, err
			}
			packet.longHdrPackets = append(packet.longHdrPackets, cont)
		} else { // [UQUIC]
			cont, err := p.appendInitialPacket(buffer, initialHdr, initialPayload, protocol.EncryptionInitial, initialSealer, v)
			if err != nil {
				return nil, err
			}

			packet.longHdrPackets = append(packet.longHdrPackets, cont)
		}
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
		shp, err := p.appendShortHeaderPacket(buffer, connID, oneRTTPacketNumber, oneRTTPacketNumberLen, kp, oneRTTPayload, 0, maxPacketSize, oneRTTSealer, false, v)
		if err != nil {
			return nil, err
		}
		packet.shortHdrPacket = &shp
	}
	return packet, nil
}

// [UQUIC]
func (p *uPacketPacker) appendInitialPacket(buffer *packetBuffer, header *wire.ExtendedHeader, pl payload, encLevel protocol.EncryptionLevel, sealer sealer, v protocol.VersionNumber) (*longHeaderPacket, error) {
	// Shouldn't need this?
	// if p.uSpec.InitialPacketSpec.InitPacketNumberLength > 0 {
	// 	header.PacketNumberLen = p.uSpec.InitialPacketSpec.InitPacketNumberLength
	// }

	uPayload, err := p.MarshalInitialPacketPayload(pl, v)
	if err != nil {
		return nil, err
	}

	pnLen := protocol.ByteCount(header.PacketNumberLen)
	header.Length = pnLen + protocol.ByteCount(sealer.Overhead()) + protocol.ByteCount(len(uPayload))

	startLen := len(buffer.Data)
	raw := buffer.Data[startLen:] // [UQUIC] the raw here is a sub-slice of buffer.Data, latter's len < size

	raw, err = header.Append(raw, v)
	if err != nil {
		return nil, err
	}
	payloadOffset := protocol.ByteCount(len(raw))
	raw = append(raw, uPayload...)

	// fmt.Printf("Payload: %x\n", raw[payloadOffset:])

	// fmt.Printf("Pre-Encryption: %x\n", raw)

	raw = p.encryptPacket(raw, sealer, header.PacketNumber, payloadOffset, pnLen)
	buffer.Data = buffer.Data[:len(buffer.Data)+len(raw)]

	// fmt.Printf("Post-Encryption: %x\n", raw)

	// [UQUIC]
	// append zero to buffer.Data until min size is reached
	minUDPSize := p.uSpec.UDPDatagramMinSize
	if minUDPSize == 0 {
		minUDPSize = DefaultUDPDatagramMinSize
	}
	if len(buffer.Data) < minUDPSize {
		buffer.Data = append(buffer.Data, make([]byte, minUDPSize-len(buffer.Data))...)
	}

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

func (p *uPacketPacker) MarshalInitialPacketPayload(pl payload, v protocol.VersionNumber) ([]byte, error) {
	var originalFrameBytes []byte

	for _, f := range pl.frames {
		var err error
		// only append crypto frames
		if _, ok := f.Frame.(*wire.CryptoFrame); !ok {
			continue
		}

		originalFrameBytes, err = f.Frame.Append(originalFrameBytes, v)
		if err != nil {
			return nil, err
		}
	}

	uPayload, err := p.uSpec.InitialPacketSpec.FrameOrder.MarshalWithFrames(originalFrameBytes)
	if err != nil {
		return nil, err
	}

	return uPayload, nil
}
