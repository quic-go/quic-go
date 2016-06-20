package frames

import (
	"bytes"
	"errors"
	"time"

	"github.com/lucas-clemente/quic-go/protocol"
	"github.com/lucas-clemente/quic-go/utils"
)

var errInvalidAckRanges = errors.New("AckFrame: ACK frame contains invalid ACK ranges")

// An AckFrameNew is a ACK frame in QUIC c34
type AckFrameNew struct {
	// TODO: rename to LargestAcked
	LargestObserved protocol.PacketNumber
	NackRanges      []NackRange // has to be ordered. The NACK range with the highest FirstPacketNumber goes first, the NACK range with the lowest FirstPacketNumber goes last
	LowestAcked     protocol.PacketNumber
	AckRanges       []AckRange

	DelayTime          time.Duration
	PacketReceivedTime time.Time // only for received packets. Will not be modified for received ACKs frames
}

// ParseAckFrameNew reads an ACK frame
func ParseAckFrameNew(r *bytes.Reader, version protocol.VersionNumber) (*AckFrameNew, error) {
	frame := &AckFrameNew{}

	typeByte, err := r.ReadByte()
	if err != nil {
		return nil, err
	}

	hasNACK := false
	if typeByte&0x20 == 0x20 {
		hasNACK = true
	}

	largestObservedLen := 2 * ((typeByte & 0x0C) >> 2)
	if largestObservedLen == 0 {
		largestObservedLen = 1
	}

	missingSequenceNumberDeltaLen := 2 * (typeByte & 0x03)
	if missingSequenceNumberDeltaLen == 0 {
		missingSequenceNumberDeltaLen = 1
	}

	largestObserved, err := utils.ReadUintN(r, largestObservedLen)
	if err != nil {
		return nil, err
	}
	frame.LargestObserved = protocol.PacketNumber(largestObserved)

	delay, err := utils.ReadUfloat16(r)
	if err != nil {
		return nil, err
	}
	frame.DelayTime = time.Duration(delay) * time.Microsecond

	var numAckBlocks uint8
	if hasNACK {
		numAckBlocks, err = r.ReadByte()
		if err != nil {
			return nil, err
		}
	}

	ackBlockLength, err := utils.ReadUintN(r, missingSequenceNumberDeltaLen)
	if err != nil {
		return nil, err
	}

	if ackBlockLength > largestObserved {
		return nil, errInvalidAckRanges
	}

	if hasNACK {
		ackRange := AckRange{
			FirstPacketNumber: protocol.PacketNumber(largestObserved-ackBlockLength) + 1,
			LastPacketNumber:  frame.LargestObserved,
		}
		frame.AckRanges = append(frame.AckRanges, ackRange)

		var inLongBlock bool
		for i := uint8(0); i < numAckBlocks; i++ {
			var gap uint8
			gap, err = r.ReadByte()
			if err != nil {
				return nil, err
			}

			ackBlockLength, err = utils.ReadUintN(r, missingSequenceNumberDeltaLen)
			if err != nil {
				return nil, err
			}

			length := protocol.PacketNumber(ackBlockLength)

			if inLongBlock {
				frame.AckRanges[len(frame.AckRanges)-1].FirstPacketNumber -= protocol.PacketNumber(gap) + length
				frame.AckRanges[len(frame.AckRanges)-1].LastPacketNumber -= protocol.PacketNumber(gap)
			} else {
				ackRange := AckRange{
					LastPacketNumber: frame.AckRanges[len(frame.AckRanges)-1].FirstPacketNumber - protocol.PacketNumber(gap) - 1,
				}
				ackRange.FirstPacketNumber = ackRange.LastPacketNumber - length + 1
				frame.AckRanges = append(frame.AckRanges, ackRange)
			}

			inLongBlock = (ackBlockLength == 0)
		}
		frame.LowestAcked = frame.AckRanges[len(frame.AckRanges)-1].FirstPacketNumber
	} else {
		// make sure that LowestAcked is not 0. 0 is not a valid PacketNumber
		// TODO: is this really the right behavior?
		if largestObserved == ackBlockLength {
			frame.LowestAcked = 1
		} else {
			frame.LowestAcked = protocol.PacketNumber(largestObserved - ackBlockLength)
		}
	}

	var numTimestampByte byte
	numTimestampByte, err = r.ReadByte()
	if err != nil {
		return nil, err
	}
	numTimestamp := uint8(numTimestampByte)

	// Delta Largest observed
	_, err = r.ReadByte()
	if err != nil {
		return nil, err
	}
	// First Timestamp
	_, err = utils.ReadUint32(r)
	if err != nil {
		return nil, err
	}

	for i := 0; i < int(numTimestamp)-1; i++ {
		// Delta Largest observed
		_, err = r.ReadByte()
		if err != nil {
			return nil, err
		}

		// Time Since Previous Timestamp
		_, err = utils.ReadUint16(r)
		if err != nil {
			return nil, err
		}
	}

	return frame, nil
}

// Write writes an ACK frame.
func (f *AckFrameNew) Write(b *bytes.Buffer, version protocol.VersionNumber) error {
	largestObservedLen := protocol.GetPacketNumberLength(f.LargestObserved)

	typeByte := uint8(0x40)

	if largestObservedLen != protocol.PacketNumberLen1 {
		typeByte ^= (uint8(largestObservedLen / 2)) << 2
	}

	missingSequenceNumberDeltaLen := largestObservedLen
	if missingSequenceNumberDeltaLen != protocol.PacketNumberLen1 {
		typeByte ^= (uint8(missingSequenceNumberDeltaLen / 2))
	}

	f.DelayTime = time.Now().Sub(f.PacketReceivedTime)

	b.WriteByte(typeByte)

	switch largestObservedLen {
	case protocol.PacketNumberLen1:
		b.WriteByte(uint8(f.LargestObserved))
	case protocol.PacketNumberLen2:
		utils.WriteUint16(b, uint16(f.LargestObserved))
	case protocol.PacketNumberLen4:
		utils.WriteUint32(b, uint32(f.LargestObserved))
	case protocol.PacketNumberLen6:
		utils.WriteUint48(b, uint64(f.LargestObserved))
	}

	utils.WriteUfloat16(b, uint64(f.DelayTime/time.Microsecond))

	// TODO: write number of ACK blocks, if present

	switch missingSequenceNumberDeltaLen {
	case protocol.PacketNumberLen1:
		b.WriteByte(uint8(f.LargestObserved))
	case protocol.PacketNumberLen2:
		utils.WriteUint16(b, uint16(f.LargestObserved))
	case protocol.PacketNumberLen4:
		utils.WriteUint32(b, uint32(f.LargestObserved))
	case protocol.PacketNumberLen6:
		utils.WriteUint48(b, uint64(f.LargestObserved))
	}

	// TODO: write ACK blocks

	b.WriteByte(0x01)       // Just one timestamp
	b.WriteByte(0x00)       // Delta Largest observed
	utils.WriteUint32(b, 0) // First timestamp

	return nil
}

// MinLength of a written frame
func (f *AckFrameNew) MinLength(version protocol.VersionNumber) (protocol.ByteCount, error) {
	var length protocol.ByteCount
	length = 1 + 2 + 1 + 1 + 4 // 1 TypeByte, 2 ACK delay time, 1 Num Timestamp, 1 Delta Largest Observed, 4 FirstTimestamp
	length += protocol.ByteCount(protocol.GetPacketNumberLength(f.LargestObserved))
	// for the first ACK block length
	length += protocol.ByteCount(protocol.GetPacketNumberLength(f.LargestObserved))

	length += (1 + 2) * 0 /* TODO: num_timestamps */
	if f.HasNACK() {
		panic("NACKs not yet implemented")
	}
	return length, nil
}

// HasNACK returns if the frame has NACK ranges
func (f *AckFrameNew) HasNACK() bool {
	if len(f.NackRanges) > 0 {
		return true
	}
	return false
}

// GetHighestInOrderPacketNumber gets the highest in order packet number that is confirmed by this ACK
func (f *AckFrameNew) GetHighestInOrderPacketNumber() protocol.PacketNumber {
	if f.HasNACK() {
		panic("NACKs not yet implemented")
	}
	return f.LargestObserved
}
