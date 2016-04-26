package quic

import (
	"bytes"
	"sync"
	"sync/atomic"

	"github.com/lucas-clemente/quic-go/crypto"
	"github.com/lucas-clemente/quic-go/frames"
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
	aead         crypto.AEAD

	queuedFrames []frames.Frame
	mutex        sync.Mutex

	lastPacketNumber protocol.PacketNumber
}

func (p *packetPacker) AddFrame(f frames.Frame) {
	p.mutex.Lock()
	p.queuedFrames = append(p.queuedFrames, f)
	p.mutex.Unlock()
}

func (p *packetPacker) PackPacket(controlFrames []frames.Frame) (*packedPacket, error) {
	// TODO: save controlFrames as a member variable, makes it easier to handle in the unlikely event that there are more controlFrames than you can put into on packet
	p.mutex.Lock()
	defer p.mutex.Unlock() // TODO: Split up?

	if len(p.queuedFrames) == 0 {
		return nil, nil
	}

	currentPacketNumber := protocol.PacketNumber(atomic.AddUint64(
		(*uint64)(&p.lastPacketNumber),
		1,
	))

	payloadFrames, err := p.composeNextPacket(controlFrames)
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
	responsePublicHeader := PublicHeader{
		ConnectionID: p.connectionID,
		PacketNumber: currentPacketNumber,
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

func (p *packetPacker) composeNextPacket(controlFrames []frames.Frame) ([]frames.Frame, error) {
	payloadLength := 0
	var payloadFrames []frames.Frame

	// TODO: handle the case where there are more controlFrames than we can put into one packet
	for len(controlFrames) > 0 {
		frame := controlFrames[0]
		payloadFrames = append(payloadFrames, frame)
		payloadLength += frame.MinLength()
		controlFrames = controlFrames[1:]
	}

	for len(p.queuedFrames) > 0 {
		frame := p.queuedFrames[0]

		if payloadLength > protocol.MaxFrameSize {
			panic("internal inconsistency: packet payload too large")
		}

		// Does the frame fit into the remaining space?
		if payloadLength+frame.MinLength() > protocol.MaxFrameSize {
			break
		}

		if streamframe, isStreamFrame := frame.(*frames.StreamFrame); isStreamFrame {
			// Split stream frames if necessary
			previousFrame := streamframe.MaybeSplitOffFrame(protocol.MaxFrameSize - payloadLength)
			if previousFrame != nil {
				// Don't pop the queue, leave the modified frame in
				frame = previousFrame
				payloadLength += len(previousFrame.Data) - 1
			} else {
				p.queuedFrames = p.queuedFrames[1:]
				payloadLength += len(streamframe.Data) - 1
			}
		} else {
			p.queuedFrames = p.queuedFrames[1:]
		}

		payloadLength += frame.MinLength()
		payloadFrames = append(payloadFrames, frame)
	}

	return payloadFrames, nil
}
