package quic

import (
	"bytes"
	"errors"
	"sync/atomic"

	"github.com/lucas-clemente/quic-go/ackhandler"
	"github.com/lucas-clemente/quic-go/crypto"
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
	connectionID protocol.ConnectionID
	version      protocol.VersionNumber
	aead         crypto.AEAD

	sentPacketHandler           ackhandler.SentPacketHandler
	connectionParametersManager *handshake.ConnectionParametersManager

	streamFrameQueue streamFrameQueue
	controlFrames    []frames.Frame
	blockedManager   *blockedManager

	lastPacketNumber protocol.PacketNumber
}

func newPacketPacker(connectionID protocol.ConnectionID, aead crypto.AEAD, sentPacketHandler ackhandler.SentPacketHandler, connectionParametersHandler *handshake.ConnectionParametersManager, version protocol.VersionNumber) *packetPacker {
	return &packetPacker{
		aead:                        aead,
		connectionID:                connectionID,
		connectionParametersManager: connectionParametersHandler,
		version:                     version,
		sentPacketHandler:           sentPacketHandler,
		blockedManager:              newBlockedManager(),
	}
}

func (p *packetPacker) AddStreamFrame(f frames.StreamFrame) {
	p.streamFrameQueue.Push(&f, false)
}

func (p *packetPacker) AddHighPrioStreamFrame(f frames.StreamFrame) {
	p.streamFrameQueue.Push(&f, true)
}

func (p *packetPacker) AddBlocked(streamID protocol.StreamID, byteOffset protocol.ByteCount) {
	// TODO: send out connection-level BlockedFrames at the right time
	// see https://github.com/lucas-clemente/quic-go/issues/113
	if streamID == 0 {
		p.controlFrames = append(p.controlFrames, &frames.BlockedFrame{StreamID: 0})
	}

	p.blockedManager.AddBlockedStream(streamID, byteOffset)
}

func (p *packetPacker) PackPacket(stopWaitingFrame *frames.StopWaitingFrame, controlFrames []frames.Frame, includeStreamFrames bool) (*packedPacket, error) {
	// don't send out packets that only contain a StopWaitingFrame
	if len(p.controlFrames) == 0 && len(controlFrames) == 0 && (p.streamFrameQueue.Len() == 0 || !includeStreamFrames) {
		return nil, nil
	}

	if len(controlFrames) > 0 {
		p.controlFrames = append(p.controlFrames, controlFrames...)
	}

	currentPacketNumber := protocol.PacketNumber(atomic.AddUint64(
		(*uint64)(&p.lastPacketNumber),
		1,
	))

	packetNumberLen := protocol.GetPacketNumberLengthForPublicHeader(currentPacketNumber, p.sentPacketHandler.GetLargestObserved())
	responsePublicHeader := &publicHeader{
		ConnectionID:         p.connectionID,
		PacketNumber:         currentPacketNumber,
		PacketNumberLen:      packetNumberLen,
		TruncateConnectionID: p.connectionParametersManager.TruncateConnectionID(),
	}

	publicHeaderLength, err := responsePublicHeader.GetLength()
	if err != nil {
		return nil, err
	}

	if stopWaitingFrame != nil {
		stopWaitingFrame.PacketNumber = currentPacketNumber
		stopWaitingFrame.PacketNumberLen = packetNumberLen
	}

	payloadFrames, err := p.composeNextPacket(stopWaitingFrame, publicHeaderLength, includeStreamFrames)
	if err != nil {
		return nil, err
	}

	payload, err := p.getPayload(payloadFrames, currentPacketNumber)
	if err != nil {
		return nil, err
	}

	entropyBit, err := utils.RandomBit()
	if err != nil {
		return nil, err
	}
	if entropyBit {
		payload[0] = 1
	}

	var raw bytes.Buffer
	if err := responsePublicHeader.WritePublicHeader(&raw); err != nil {
		return nil, err
	}

	ciphertext := p.aead.Seal(currentPacketNumber, raw.Bytes(), payload)
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
	payload.WriteByte(0) // The entropy bit is set in sendPayload
	for _, frame := range frames {
		frame.Write(&payload, p.version)
	}
	return payload.Bytes(), nil
}

func (p *packetPacker) composeNextPacket(stopWaitingFrame *frames.StopWaitingFrame, publicHeaderLength protocol.ByteCount, includeStreamFrames bool) ([]frames.Frame, error) {
	var payloadLength protocol.ByteCount
	var payloadFrames []frames.Frame

	maxFrameSize := protocol.MaxFrameAndPublicHeaderSize - publicHeaderLength

	if stopWaitingFrame != nil {
		payloadFrames = append(payloadFrames, stopWaitingFrame)
		minLength, err := stopWaitingFrame.MinLength()
		if err != nil {
			return nil, err
		}
		payloadLength += minLength
	}

	for len(p.controlFrames) > 0 {
		frame := p.controlFrames[0]
		minLength, _ := frame.MinLength() // controlFrames does not contain any StopWaitingFrames. So it will *never* return an error
		if payloadLength+minLength > maxFrameSize {
			break
		}
		payloadFrames = append(payloadFrames, frame)
		payloadLength += minLength
		p.controlFrames = p.controlFrames[1:]
	}

	if payloadLength > maxFrameSize {
		return nil, errors.New("PacketPacker BUG: packet payload too large")
	}

	if !includeStreamFrames {
		return payloadFrames, nil
	}

	hasStreamFrames := false

	// temporarily increase the maxFrameSize by 2 bytes
	// this leads to a properly sized packet in all cases, since we do all the packet length calculations with StreamFrames that have the DataLen set
	// however, for the last StreamFrame in the packet, we can omit the DataLen, thus saving 2 bytes and yielding a packet of exactly the correct size
	maxFrameSize += 2

	for p.streamFrameQueue.Len() > 0 {
		frame := p.streamFrameQueue.Front()
		frame.DataLenPresent = true // set the dataLen by default. Remove them later if applicable

		if payloadLength > maxFrameSize {
			return nil, errors.New("PacketPacker BUG: packet payload too large")
		}

		// Does the frame fit into the remaining space?
		frameMinLength, _ := frame.MinLength() // StreamFrame.MinLength *never* returns an error
		if payloadLength+frameMinLength > maxFrameSize {
			break
		}

		// Split stream frames if necessary
		previousFrame := frame.MaybeSplitOffFrame(maxFrameSize - payloadLength)
		if previousFrame != nil {
			// Don't pop the queue, leave the modified frame in
			frame = previousFrame
			payloadLength += protocol.ByteCount(len(previousFrame.Data)) - 1
		} else {
			p.streamFrameQueue.Pop()
			payloadLength += protocol.ByteCount(len(frame.Data)) - 1
		}

		blockedFrame := p.blockedManager.GetBlockedFrame(frame.StreamID, frame.Offset+protocol.ByteCount(len(frame.Data)))
		if blockedFrame != nil {
			blockedLength, _ := blockedFrame.MinLength() // BlockedFrame.MinLength *never* returns an error
			if payloadLength+frameMinLength+blockedLength <= maxFrameSize {
				payloadFrames = append(payloadFrames, blockedFrame)
				payloadLength += blockedLength
			} else {
				p.controlFrames = append(p.controlFrames, blockedFrame)
			}
		}

		payloadLength += frameMinLength
		payloadFrames = append(payloadFrames, frame)
		hasStreamFrames = true
	}

	// remove the dataLen for the last StreamFrame in the packet
	if hasStreamFrames {
		lastStreamFrame, ok := payloadFrames[len(payloadFrames)-1].(*frames.StreamFrame)
		if !ok {
			return nil, errors.New("PacketPacker BUG: StreamFrame type assertion failed")
		}
		lastStreamFrame.DataLenPresent = false
		// payloadLength -= 2
	}

	return payloadFrames, nil
}

// Empty returns true if no frames are queued
func (p *packetPacker) Empty() bool {
	return p.streamFrameQueue.Front() == nil
}

func (p *packetPacker) StreamFrameQueueByteLen() protocol.ByteCount {
	return p.streamFrameQueue.ByteLen()
}
