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
	payload    []byte
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

func (p *packetPacker) PackPacket() (*packedPacket, error) {
	p.mutex.Lock()
	defer p.mutex.Unlock() // TODO: Split up?

	if len(p.queuedFrames) == 0 {
		return nil, nil
	}

	payload, err := p.composeNextPayload()
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

	currentPacketNumber := protocol.PacketNumber(atomic.AddUint64(
		(*uint64)(&p.lastPacketNumber),
		1,
	))
	var raw bytes.Buffer
	responsePublicHeader := PublicHeader{
		ConnectionID: p.connectionID,
		PacketNumber: currentPacketNumber,
	}
	if err := responsePublicHeader.WritePublicHeader(&raw); err != nil {
		return nil, err
	}

	ciphertext := p.aead.Seal(p.lastPacketNumber, raw.Bytes(), payload)
	raw.Write(ciphertext)

	if raw.Len() > protocol.MaxPacketSize {
		panic("internal inconsistency: packet too large")
	}

	return &packedPacket{
		number:     currentPacketNumber,
		entropyBit: entropyBit,
		raw:        raw.Bytes(),
		payload:    payload[1:],
	}, nil
}

func (p *packetPacker) composeNextPayload() ([]byte, error) {
	var payload bytes.Buffer
	payload.WriteByte(0) // The entropy bit is set in sendPayload

	for len(p.queuedFrames) > 0 {
		frame := p.queuedFrames[0]

		if payload.Len()-1 > protocol.MaxFrameSize {
			panic("internal inconsistency: packet payload too large")
		}

		// Does the frame fit into the remaining space?
		if payload.Len()-1+frame.MaxLength() > protocol.MaxFrameSize {
			return payload.Bytes(), nil
		}

		if streamframe, isStreamFrame := frame.(*frames.StreamFrame); isStreamFrame {
			// Split stream frames if necessary
			previousFrame := streamframe.MaybeSplitOffFrame(protocol.MaxFrameSize - (payload.Len() - 1))
			if previousFrame != nil {
				// Don't pop the queue, leave the modified frame in
				frame = previousFrame
			} else {
				p.queuedFrames = p.queuedFrames[1:]
			}
		} else {
			p.queuedFrames = p.queuedFrames[1:]
		}

		if err := frame.Write(&payload); err != nil {
			return nil, err
		}
	}
	return payload.Bytes(), nil
}
