package quic

import (
	"bytes"
	"sync/atomic"

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
	connectionID                protocol.ConnectionID
	aead                        crypto.AEAD
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

	payloadFrames, err := p.composeNextPacket(stopWaitingFrame, controlFrames, includeStreamFrames)
	if err != nil {
		return nil, err
	}

	if len(payloadFrames) == 0 {
		return nil, nil
	}

	currentPacketNumber := protocol.PacketNumber(atomic.AddUint64(
		(*uint64)(&p.lastPacketNumber),
		1,
	))

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
	responsePublicHeader := PublicHeader{
		ConnectionID:         p.connectionID,
		PacketNumber:         currentPacketNumber,
		TruncateConnectionID: p.connectionParametersManager.TruncateConnectionID(),
	}
	if err := responsePublicHeader.WritePublicHeader(&raw); err != nil {
		return nil, err
	}

	ciphertext := p.aead.Seal(currentPacketNumber, raw.Bytes(), payload)
	raw.Write(ciphertext)

	if raw.Len() > protocol.MaxPacketSize {
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
		frame.Write(&payload, currentPacketNumber, 6)
	}
	return payload.Bytes(), nil
}

func (p *packetPacker) composeNextPacket(stopWaitingFrame *frames.StopWaitingFrame, controlFrames []frames.Frame, includeStreamFrames bool) ([]frames.Frame, error) {
	payloadLength := 0
	var payloadFrames []frames.Frame

	// don't send out packets that only contain a StopWaitingFrame
	if len(controlFrames) == 0 && p.streamFrameQueue.Len() == 0 {
		return nil, nil
	}

	// TODO: handle the case where there are more controlFrames than we can put into one packet
	if stopWaitingFrame != nil {
		payloadFrames = append(payloadFrames, stopWaitingFrame)
		payloadLength += stopWaitingFrame.MinLength()
	}

	for len(controlFrames) > 0 {
		frame := controlFrames[0]
		payloadFrames = append(payloadFrames, frame)
		payloadLength += frame.MinLength()
		controlFrames = controlFrames[1:]
	}

	if payloadLength > protocol.MaxFrameSize {
		panic("internal inconsistency: packet payload too large")
	}

	if !includeStreamFrames {
		return payloadFrames, nil
	}

	for p.streamFrameQueue.Len() > 0 {
		frame := p.streamFrameQueue.Front()

		if payloadLength > protocol.MaxFrameSize {
			panic("internal inconsistency: packet payload too large")
		}

		// Does the frame fit into the remaining space?
		if payloadLength+frame.MinLength() > protocol.MaxFrameSize {
			break
		}

		// Split stream frames if necessary
		previousFrame := frame.MaybeSplitOffFrame(protocol.MaxFrameSize - payloadLength)
		if previousFrame != nil {
			// Don't pop the queue, leave the modified frame in
			frame = previousFrame
			payloadLength += len(previousFrame.Data) - 1
		} else {
			p.streamFrameQueue.Pop()
			payloadLength += len(frame.Data) - 1
		}

		payloadLength += frame.MinLength()
		payloadFrames = append(payloadFrames, frame)
	}

	return payloadFrames, nil
}

// Empty returns true if no frames are queued
func (p *packetPacker) Empty() bool {
	return p.streamFrameQueue.Front() == nil
}
