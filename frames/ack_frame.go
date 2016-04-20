package frames

import (
	"bytes"
	"errors"

	"github.com/lucas-clemente/quic-go/protocol"
	"github.com/lucas-clemente/quic-go/utils"
)

// NackRange is a NACK range
type NackRange struct {
	FirstPacketNumber protocol.PacketNumber
	Length            uint8
}

// An AckFrame in QUIC
type AckFrame struct {
	Entropy         byte
	LargestObserved protocol.PacketNumber
	DelayTime       uint16      // Todo: properly interpret this value as described in the specification
	NackRanges      []NackRange // has to be ordered. The NACK range with the highest FirstPacketNumber goes first, the NACK range with the lowest FirstPacketNumber goes last
}

// Write writes an ACK frame.
func (f *AckFrame) Write(b *bytes.Buffer) error {
	typeByte := uint8(0x40 | 0x0C)

	if f.HasNACK() {
		typeByte |= (0x20 | 0x03)
	}

	b.WriteByte(typeByte)
	b.WriteByte(f.Entropy)
	utils.WriteUint48(b, uint64(f.LargestObserved)) // TODO: send the correct length
	utils.WriteUint16(b, 1)                         // TODO: Ack delay time
	b.WriteByte(0x01)                               // Just one timestamp
	b.WriteByte(0x00)                               // Delta Largest observed
	utils.WriteUint32(b, 0)                         // First timestamp

	if f.HasNACK() {
		numRanges := uint8(len(f.NackRanges))
		b.WriteByte(numRanges)

		for i, nackRange := range f.NackRanges {
			var missingPacketSequenceNumberDelta uint64
			if i == 0 {
				if protocol.PacketNumber(uint64(nackRange.FirstPacketNumber)+uint64(nackRange.Length)) > f.LargestObserved {
					return errors.New("AckFrame: Invalid NACK ranges")
				}
				missingPacketSequenceNumberDelta = uint64(f.LargestObserved-nackRange.FirstPacketNumber) - uint64(nackRange.Length) + 1
			} else {
				lastNackRange := f.NackRanges[i-1]
				missingPacketSequenceNumberDelta = uint64(lastNackRange.FirstPacketNumber-nackRange.FirstPacketNumber) - uint64(nackRange.Length)
			}
			rangeLength := nackRange.Length - 1
			if rangeLength > 255 {
				return errors.New("AckFrame: NACK ranges larger 256 packets not yet supported")
			}
			utils.WriteUint48(b, missingPacketSequenceNumberDelta)
			b.WriteByte(rangeLength)
		}
	}

	return nil
}

// MaxLength of a written frame
func (f *AckFrame) MaxLength() int {
	l := 1 + 1 + 6 + 2 + 1 + 1 + 4
	l += (1 + 2) * 0 /* TODO: num_timestamps */
	if f.HasNACK() {
		l += 1 + (6+1)*len(f.NackRanges)
	}
	return l
}

// HasNACK returns if the frame has NACK ranges
func (f *AckFrame) HasNACK() bool {
	if len(f.NackRanges) > 0 {
		return true
	}
	return false
}

// GetHighestInOrderPacket gets the highest in order packet number that is confirmed by this ACK
func (f *AckFrame) GetHighestInOrderPacket() protocol.PacketNumber {
	if f.HasNACK() {
		return (f.NackRanges[len(f.NackRanges)-1].FirstPacketNumber - 1)
	}
	return f.LargestObserved
}

// ParseAckFrame reads an ACK frame
func ParseAckFrame(r *bytes.Reader) (*AckFrame, error) {
	frame := &AckFrame{}

	typeByte, err := r.ReadByte()
	if err != nil {
		return nil, err
	}

	hasNACK := false
	if typeByte&0x20 == 0x20 {
		hasNACK = true
	}
	if typeByte&0x10 == 0x10 {
		panic("truncated ACKs not yet implemented.")
	}

	largestObservedLen := 2 * ((typeByte & 0x0C) >> 2)
	if largestObservedLen == 0 {
		largestObservedLen = 1
	}

	missingSequenceNumberDeltaLen := 2 * (typeByte & 0x03)
	if missingSequenceNumberDeltaLen == 0 {
		missingSequenceNumberDeltaLen = 1
	}

	frame.Entropy, err = r.ReadByte()
	if err != nil {
		return nil, err
	}

	largestObserved, err := utils.ReadUintN(r, largestObservedLen)
	if err != nil {
		return nil, err
	}
	frame.LargestObserved = protocol.PacketNumber(largestObserved)

	frame.DelayTime, err = utils.ReadUint16(r)
	if err != nil {
		return nil, err
	}

	numTimestampByte, err := r.ReadByte()
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

	if hasNACK {
		var numRanges uint8
		numRanges, err = r.ReadByte()
		if err != nil {
			return nil, err
		}

		for i := uint8(0); i < numRanges; i++ {
			missingPacketSequenceNumberDelta, err := utils.ReadUintN(r, missingSequenceNumberDeltaLen)
			if err != nil {
				return nil, err
			}

			rangeLengthByte, err := r.ReadByte()
			if err != nil {
				return nil, err
			}
			rangeLength := uint8(rangeLengthByte)

			nackRange := NackRange{
				Length: uint8(rangeLength + 1),
			}
			if i == 0 {
				nackRange.FirstPacketNumber = frame.LargestObserved - protocol.PacketNumber(missingPacketSequenceNumberDelta+uint64(rangeLength))
			} else {
				if missingPacketSequenceNumberDelta == 0 {
					return nil, errors.New("ACK frame: Continues NACK ranges not yet implemented")
				}
				lastNackRange := frame.NackRanges[len(frame.NackRanges)-1]
				nackRange.FirstPacketNumber = lastNackRange.FirstPacketNumber - protocol.PacketNumber(missingPacketSequenceNumberDelta+uint64(rangeLength)) - 1
			}
			frame.NackRanges = append(frame.NackRanges, nackRange)
		}
	}

	return frame, nil
}
