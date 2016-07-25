package quic

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/lucas-clemente/quic-go/frames"
	"github.com/lucas-clemente/quic-go/handshake"
	"github.com/lucas-clemente/quic-go/protocol"
	"github.com/lucas-clemente/quic-go/utils"
)

type packedPacket struct {
	number     protocol.PacketNumber
	entropyBit bool
	raw        []byte
	frames     []frames.Frame
}

type packetPacker struct {
	connectionID     protocol.ConnectionID
	version          protocol.VersionNumber
	cryptoSetup      *handshake.CryptoSetup
	lastPacketNumber protocol.PacketNumber

	connectionParametersManager *handshake.ConnectionParametersManager

	streamFramer  *streamFramer
	controlFrames []frames.Frame
}

func newPacketPacker(connectionID protocol.ConnectionID, cryptoSetup *handshake.CryptoSetup, connectionParametersHandler *handshake.ConnectionParametersManager, streamFramer *streamFramer, version protocol.VersionNumber) *packetPacker {
	return &packetPacker{
		cryptoSetup:                 cryptoSetup,
		connectionID:                connectionID,
		connectionParametersManager: connectionParametersHandler,
		version:                     version,
		streamFramer:                streamFramer,
	}
}

func (p *packetPacker) PackConnectionClose(frame *frames.ConnectionCloseFrame, largestObserved protocol.PacketNumber) (*packedPacket, error) {
	return p.packPacket(nil, []frames.Frame{frame}, largestObserved, true)
}

func (p *packetPacker) PackPacket(stopWaitingFrame *frames.StopWaitingFrame, controlFrames []frames.Frame, largestObserved protocol.PacketNumber) (*packedPacket, error) {
	return p.packPacket(stopWaitingFrame, controlFrames, largestObserved, false)
}

func (p *packetPacker) packPacket(stopWaitingFrame *frames.StopWaitingFrame, controlFrames []frames.Frame, largestObserved protocol.PacketNumber, onlySendOneControlFrame bool) (*packedPacket, error) {
	// don't send out packets that only contain a StopWaitingFrame
	if len(p.controlFrames) == 0 && len(controlFrames) == 0 && !p.streamFramer.HasData() {
		return nil, nil
	}

	if len(controlFrames) > 0 {
		p.controlFrames = append(p.controlFrames, controlFrames...)
	}

	p.lastPacketNumber++
	currentPacketNumber := p.lastPacketNumber

	// cryptoSetup needs to be locked here, so that the AEADs are not changed between
	// calling DiversificationNonce() and Seal().
	p.cryptoSetup.LockForSealing()
	defer p.cryptoSetup.UnlockForSealing()

	packetNumberLen := protocol.GetPacketNumberLengthForPublicHeader(currentPacketNumber, largestObserved)
	responsePublicHeader := &publicHeader{
		ConnectionID:         p.connectionID,
		PacketNumber:         currentPacketNumber,
		PacketNumberLen:      packetNumberLen,
		TruncateConnectionID: p.connectionParametersManager.TruncateConnectionID(),
		DiversificationNonce: p.cryptoSetup.DiversificationNonce(),
	}

	publicHeaderLength, err := responsePublicHeader.GetLength()
	if err != nil {
		return nil, err
	}

	if stopWaitingFrame != nil {
		stopWaitingFrame.PacketNumber = currentPacketNumber
		stopWaitingFrame.PacketNumberLen = packetNumberLen
	}

	var payloadFrames []frames.Frame
	if onlySendOneControlFrame {
		payloadFrames = []frames.Frame{controlFrames[0]}
	} else {
		payloadFrames, err = p.composeNextPacket(stopWaitingFrame, publicHeaderLength)
		if err != nil {
			return nil, err
		}
	}

	payload, err := p.getPayload(payloadFrames, currentPacketNumber)
	if err != nil {
		return nil, err
	}

	// set entropy bit in Private Header, for QUIC version < 34
	var entropyBit bool
	if p.version < protocol.Version34 {
		entropyBit, err = utils.RandomBit()
		if err != nil {
			return nil, err
		}
		if entropyBit {
			payload[0] = 1
		}
	}

	var raw bytes.Buffer
	if err := responsePublicHeader.WritePublicHeader(&raw, p.version); err != nil {
		return nil, err
	}

	ciphertext := p.cryptoSetup.Seal(currentPacketNumber, raw.Bytes(), payload)
	raw.Write(ciphertext)

	if protocol.ByteCount(raw.Len()) > protocol.MaxPacketSize {
		return nil, errors.New("PacketPacker BUG: packet too large")
	}

	return &packedPacket{
		number:     currentPacketNumber,
		entropyBit: entropyBit,
		raw:        raw.Bytes(),
		frames:     payloadFrames,
	}, nil
}

func (p *packetPacker) getPayload(frames []frames.Frame, currentPacketNumber protocol.PacketNumber) ([]byte, error) {
	var payload bytes.Buffer

	// reserve 1 byte for the Private Header, for QUIC Version < 34
	// the entropy bit is set in sendPayload
	if p.version < protocol.Version34 {
		payload.WriteByte(0)
	}

	for _, frame := range frames {
		frame.Write(&payload, p.version)
	}
	return payload.Bytes(), nil
}

func (p *packetPacker) composeNextPacket(stopWaitingFrame *frames.StopWaitingFrame, publicHeaderLength protocol.ByteCount) ([]frames.Frame, error) {
	var payloadLength protocol.ByteCount
	var payloadFrames []frames.Frame

	maxFrameSize := protocol.MaxFrameAndPublicHeaderSize - publicHeaderLength

	// until QUIC 33, packets have a 1 byte private header
	if p.version < protocol.Version34 {
		maxFrameSize--
	}

	if stopWaitingFrame != nil {
		payloadFrames = append(payloadFrames, stopWaitingFrame)
		minLength, err := stopWaitingFrame.MinLength(p.version)
		if err != nil {
			return nil, err
		}
		payloadLength += minLength
	}

	for len(p.controlFrames) > 0 {
		frame := p.controlFrames[0]
		minLength, _ := frame.MinLength(p.version) // controlFrames does not contain any StopWaitingFrames. So it will *never* return an error
		if payloadLength+minLength > maxFrameSize {
			break
		}
		payloadFrames = append(payloadFrames, frame)
		payloadLength += minLength
		p.controlFrames = p.controlFrames[1:]
	}

	if payloadLength > maxFrameSize {
		return nil, fmt.Errorf("Packet Packer BUG: packet payload (%d) too large (%d)", payloadLength, maxFrameSize)
	}

	// temporarily increase the maxFrameSize by 2 bytes
	// this leads to a properly sized packet in all cases, since we do all the packet length calculations with StreamFrames that have the DataLen set
	// however, for the last StreamFrame in the packet, we can omit the DataLen, thus saving 2 bytes and yielding a packet of exactly the correct size
	maxFrameSize += 2

	fs := p.streamFramer.PopStreamFrames(maxFrameSize - payloadLength)
	if len(fs) != 0 {
		fs[len(fs)-1].DataLenPresent = false
	}

	// TODO: Simplify
	for _, f := range fs {
		payloadFrames = append(payloadFrames, f)
	}

	for b := p.streamFramer.PopBlockedFrame(); b != nil; b = p.streamFramer.PopBlockedFrame() {
		p.controlFrames = append(p.controlFrames, b)
	}

	return payloadFrames, nil
}

func (p *packetPacker) QueueControlFrameForNextPacket(f frames.Frame) {
	p.controlFrames = append(p.controlFrames, f)
}
