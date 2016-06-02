package quic

import (
	"bytes"
	"errors"
	"sync/atomic"

	"github.com/lucas-clemente/quic-go/ackhandler"
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
	cryptoSetup  *handshake.CryptoSetup

	sentPacketHandler           ackhandler.SentPacketHandler
	connectionParametersManager *handshake.ConnectionParametersManager

	streamFrameQueue *streamFrameQueue
	controlFrames    []frames.Frame
	blockedManager   *blockedManager

	lastPacketNumber protocol.PacketNumber
}

func newPacketPacker(connectionID protocol.ConnectionID, cryptoSetup *handshake.CryptoSetup, sentPacketHandler ackhandler.SentPacketHandler, connectionParametersHandler *handshake.ConnectionParametersManager, blockedManager *blockedManager, version protocol.VersionNumber) *packetPacker {
	return &packetPacker{
		cryptoSetup:                 cryptoSetup,
		connectionID:                connectionID,
		connectionParametersManager: connectionParametersHandler,
		version:                     version,
		sentPacketHandler:           sentPacketHandler,
		blockedManager:              blockedManager,
		streamFrameQueue:            newStreamFrameQueue(),
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
	// TODO: remove this function completely once #113 is resolved
	if streamID == 0 {
		p.controlFrames = append(p.controlFrames, &frames.BlockedFrame{StreamID: 0})
	}

	p.blockedManager.AddBlockedStream(streamID, byteOffset)
}

func (p *packetPacker) PackConnectionClose(frame *frames.ConnectionCloseFrame) (*packedPacket, error) {
	return p.packPacket(nil, []frames.Frame{frame}, true)
}

func (p *packetPacker) PackPacket(stopWaitingFrame *frames.StopWaitingFrame, controlFrames []frames.Frame) (*packedPacket, error) {
	return p.packPacket(stopWaitingFrame, controlFrames, false)
}

func (p *packetPacker) packPacket(stopWaitingFrame *frames.StopWaitingFrame, controlFrames []frames.Frame, onlySendOneControlFrame bool) (*packedPacket, error) {
	// don't send out packets that only contain a StopWaitingFrame
	if len(p.controlFrames) == 0 && len(controlFrames) == 0 && p.streamFrameQueue.Len() == 0 {
		return nil, nil
	}

	if len(controlFrames) > 0 {
		p.controlFrames = append(p.controlFrames, controlFrames...)
	}

	currentPacketNumber := protocol.PacketNumber(atomic.AddUint64(
		(*uint64)(&p.lastPacketNumber),
		1,
	))

	// cryptoSetup needs to be locked here, so that the AEADs are not changed between
	// calling DiversificationNonce() and Seal().
	p.cryptoSetup.LockForSealing()
	defer p.cryptoSetup.UnlockForSealing()

	packetNumberLen := protocol.GetPacketNumberLengthForPublicHeader(currentPacketNumber, p.sentPacketHandler.GetLargestObserved())
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

	entropyBit, err := utils.RandomBit()
	if err != nil {
		return nil, err
	}
	if entropyBit {
		payload[0] = 1
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
	payload.WriteByte(0) // The entropy bit is set in sendPayload
	for _, frame := range frames {
		frame.Write(&payload, p.version)
	}
	return payload.Bytes(), nil
}

func (p *packetPacker) composeNextPacket(stopWaitingFrame *frames.StopWaitingFrame, publicHeaderLength protocol.ByteCount) ([]frames.Frame, error) {
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

	hasStreamFrames := false

	// temporarily increase the maxFrameSize by 2 bytes
	// this leads to a properly sized packet in all cases, since we do all the packet length calculations with StreamFrames that have the DataLen set
	// however, for the last StreamFrame in the packet, we can omit the DataLen, thus saving 2 bytes and yielding a packet of exactly the correct size
	maxFrameSize += 2

	for p.streamFrameQueue.Len() > 0 {
		if payloadLength > maxFrameSize {
			return nil, errors.New("PacketPacker BUG: packet payload too large")
		}

		frame, err := p.streamFrameQueue.Pop(maxFrameSize - payloadLength)
		if err != nil {
			return nil, err
		}
		if frame == nil {
			break
		}
		frame.DataLenPresent = true // set the dataLen by default. Remove them later if applicable

		frameMinLength, _ := frame.MinLength() // StreamFrame.MinLength *never* returns an error
		payloadLength += frameMinLength - 1 + frame.DataLen()

		blockedFrame := p.blockedManager.GetBlockedFrame(frame.StreamID, frame.Offset+frame.DataLen())
		if blockedFrame != nil {
			blockedLength, _ := blockedFrame.MinLength() // BlockedFrame.MinLength *never* returns an error
			if payloadLength+blockedLength <= maxFrameSize {
				payloadFrames = append(payloadFrames, blockedFrame)
				payloadLength += blockedLength
			} else {
				p.controlFrames = append(p.controlFrames, blockedFrame)
			}
		}

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
	return p.streamFrameQueue.ByteLen() == 0
}

func (p *packetPacker) StreamFrameQueueByteLen() protocol.ByteCount {
	return p.streamFrameQueue.ByteLen()
}
