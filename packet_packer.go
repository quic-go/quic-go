package quic

import (
	"bytes"
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

	streamFrameQueue StreamFrameQueue

	lastPacketNumber protocol.PacketNumber
}

func (p *packetPacker) AddStreamFrame(f frames.StreamFrame) {
	p.streamFrameQueue.Push(&f, false)
}

func (p *packetPacker) AddHighPrioStreamFrame(f frames.StreamFrame) {
	p.streamFrameQueue.Push(&f, true)
}

func (p *packetPacker) PackPacket(stopWaitingFrame *frames.StopWaitingFrame, controlFrames []frames.Frame, includeStreamFrames bool) (*packedPacket, error) {
	// TODO: save controlFrames as a member variable, makes it easier to handle in the unlikely event that there are more controlFrames than you can put into on packet

	// don't send out packets that only contain a StopWaitingFrame
	if len(controlFrames) == 0 && (p.streamFrameQueue.Len() == 0 || !includeStreamFrames) {
		return nil, nil
	}

	currentPacketNumber := protocol.PacketNumber(atomic.AddUint64(
		(*uint64)(&p.lastPacketNumber),
		1,
	))

	packetNumberLen := getPacketNumberLength(currentPacketNumber, p.sentPacketHandler.GetLargestObserved())
	responsePublicHeader := &PublicHeader{
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

	payloadFrames, err := p.composeNextPacket(stopWaitingFrame, controlFrames, publicHeaderLength, includeStreamFrames)
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
		panic("internal inconsistency: packet too large")
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

func (p *packetPacker) composeNextPacket(stopWaitingFrame *frames.StopWaitingFrame, controlFrames []frames.Frame, publicHeaderLength protocol.ByteCount, includeStreamFrames bool) ([]frames.Frame, error) {
	payloadLength := protocol.ByteCount(0)
	var payloadFrames []frames.Frame

	// TODO: handle the case where there are more controlFrames than we can put into one packet
	if stopWaitingFrame != nil {
		payloadFrames = append(payloadFrames, stopWaitingFrame)
		minLength, err := stopWaitingFrame.MinLength()
		if err != nil {
			return nil, err
		}
		payloadLength += minLength
	}

	for len(controlFrames) > 0 {
		frame := controlFrames[0]
		payloadFrames = append(payloadFrames, frame)
		minLength, _ := frame.MinLength() // controlFrames does not contain any StopWaitingFrames. So it will *never* return an error
		payloadLength += minLength
		controlFrames = controlFrames[1:]
	}

	maxFrameSize := protocol.MaxFrameAndPublicHeaderSize - publicHeaderLength

	if payloadLength > maxFrameSize {
		panic("internal inconsistency: packet payload too large")
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
			panic("internal inconsistency: packet payload too large")
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

		payloadLength += frameMinLength
		payloadFrames = append(payloadFrames, frame)
		hasStreamFrames = true
	}

	// remove the dataLen for the last StreamFrame in the packet
	if hasStreamFrames {
		payloadFrames[len(payloadFrames)-1].(*frames.StreamFrame).DataLenPresent = false
		// payloadLength -= 2
	}

	return payloadFrames, nil
}

// Empty returns true if no frames are queued
func (p *packetPacker) Empty() bool {
	return p.streamFrameQueue.Front() == nil
}
