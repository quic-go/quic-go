package frames

import (
	"bytes"
	"errors"
	"time"

	"github.com/lucas-clemente/quic-go/protocol"
	"github.com/lucas-clemente/quic-go/utils"
)

var errInvalidNackRanges = errors.New("AckFrame: ACK frame contains invalid NACK ranges")

// An AckFrame in QUIC
type AckFrame struct {
	LargestObserved protocol.PacketNumber
	Entropy         byte
	NackRanges      []NackRange // has to be ordered. The NACK range with the highest FirstPacketNumber goes first, the NACK range with the lowest FirstPacketNumber goes last
	Truncated       bool

	DelayTime          time.Duration
	PacketReceivedTime time.Time // only for received packets. Will not be modified for received ACKs frames
}

// Write writes an ACK frame.
func (f *AckFrame) Write(b *bytes.Buffer, version protocol.VersionNumber) error {
	largestObservedLen := protocol.GetPacketNumberLength(f.LargestObserved)

	typeByte := uint8(0x40)

	if largestObservedLen != protocol.PacketNumberLen1 {
		typeByte ^= (uint8(largestObservedLen / 2)) << 2
	}

	if f.HasNACK() {
		typeByte |= (0x20 | 0x03)
	}

	f.DelayTime = time.Now().Sub(f.PacketReceivedTime)

	b.WriteByte(typeByte)
	b.WriteByte(f.Entropy)

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
	b.WriteByte(0x01)       // Just one timestamp
	b.WriteByte(0x00)       // Delta Largest observed
	utils.WriteUint32(b, 0) // First timestamp

	if f.HasNACK() {
		numRanges := uint64(0)
		// calculate the number of NackRanges that are about to be written
		// this number is different from len(f.NackRanges) for the case of contiguous NACK ranges
		for _, nackRange := range f.NackRanges {
			rangeLength := nackRange.Len()
			numRanges += rangeLength/0xFF + 1
			if rangeLength > 0 && rangeLength%0xFF == 0 {
				numRanges--
			}
		}
		if numRanges > 0xFF {
			panic("Too many NACK ranges. Truncating not yet implemented.")
		}

		b.WriteByte(uint8(numRanges))

		rangeCounter := uint8(0)
		for i, nackRange := range f.NackRanges {
			var missingPacketSequenceNumberDelta uint64
			if i == 0 {
				if nackRange.LastPacketNumber > f.LargestObserved {
					return errors.New("AckFrame: Invalid NACK ranges")
				}
				missingPacketSequenceNumberDelta = uint64(f.LargestObserved) - uint64(nackRange.LastPacketNumber)
			} else {
				lastNackRange := f.NackRanges[i-1]
				missingPacketSequenceNumberDelta = uint64(lastNackRange.FirstPacketNumber) - uint64(nackRange.LastPacketNumber) - 1
			}
			rangeLength := nackRange.Len()

			utils.WriteUint48(b, missingPacketSequenceNumberDelta)
			b.WriteByte(uint8(rangeLength % 0x100))
			rangeCounter++

			rangeLength = rangeLength - (rangeLength % 0x100)
			for rangeLength > 0 {
				rangeCounter++
				utils.WriteUint48(b, 0)
				b.WriteByte(uint8(0xFF))
				rangeLength -= 0x100
			}
		}

		if rangeCounter != uint8(numRanges) {
			return errors.New("BUG: Inconsistent number of NACK ranges written")
		}

		// TODO: Remove once we drop support for <32
		if version < protocol.Version32 {
			b.WriteByte(0)
		}
	}

	return nil
}

// MinLength of a written frame
func (f *AckFrame) MinLength() (protocol.ByteCount, error) {
	l := 1 + 1 + 2 + 1 + 1 + 4 // 1 TypeByte, 1 Entropy, 2 ACK delay time, 1 Num Timestamp, 1 Delta Largest Observed, 4 FirstTimestamp
	l += int(protocol.GetPacketNumberLength(f.LargestObserved))
	l += (1 + 2) * 0 /* TODO: num_timestamps */
	if f.HasNACK() {
		l += 1 + (6+1)*len(f.NackRanges)
		l++ // TODO: Remove once we drop support for <32
	}
	return protocol.ByteCount(l), nil
}

// HasNACK returns if the frame has NACK ranges
func (f *AckFrame) HasNACK() bool {
	if len(f.NackRanges) > 0 {
		return true
	}
	return false
}

// GetHighestInOrderPacketNumber gets the highest in order packet number that is confirmed by this ACK
func (f *AckFrame) GetHighestInOrderPacketNumber() protocol.PacketNumber {
	if f.HasNACK() {
		return (f.NackRanges[len(f.NackRanges)-1].FirstPacketNumber - 1)
	}
	return f.LargestObserved
}

// ParseAckFrame reads an ACK frame
func ParseAckFrame(r *bytes.Reader, version protocol.VersionNumber) (*AckFrame, error) {
	frame := &AckFrame{}

	typeByte, err := r.ReadByte()
	if err != nil {
		return nil, err
	}

	hasNACK := false
	if typeByte&0x20 == 0x20 {
		hasNACK = true
	}
	frame.Truncated = typeByte&0x10 > 0

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

	delay, err := utils.ReadUfloat16(r)
	if err != nil {
		return nil, err
	}
	frame.DelayTime = time.Duration(delay) * time.Microsecond

	if !frame.Truncated {
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
	}

	// Invalid NACK Handling:
	// NACKs contain a lot of offsets that require subtractions of PacketNumbers. If an ACK contains invalid data, it is possible to underflow the uint64 used to store the PacketNumber
	// TODO: handle uint64 overflows
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

			// contiguous NACK range
			if i > 0 && missingPacketSequenceNumberDelta == 0 {
				nackRange := &frame.NackRanges[len(frame.NackRanges)-1]
				if uint64(nackRange.FirstPacketNumber) <= uint64(rangeLength)+1 {
					return nil, errInvalidNackRanges
				}
				nackRange.FirstPacketNumber = protocol.PacketNumber(uint64(nackRange.FirstPacketNumber) - uint64(rangeLength) - 1)
			} else {
				nackRange := NackRange{}
				if i == 0 {
					if uint64(frame.LargestObserved) < missingPacketSequenceNumberDelta+uint64(rangeLength) {
						return nil, errInvalidNackRanges
					}
					nackRange.FirstPacketNumber = frame.LargestObserved - protocol.PacketNumber(missingPacketSequenceNumberDelta+uint64(rangeLength))
				} else {
					lastNackRange := frame.NackRanges[len(frame.NackRanges)-1]
					if uint64(lastNackRange.FirstPacketNumber) <= missingPacketSequenceNumberDelta+uint64(rangeLength) {
						return nil, errInvalidNackRanges
					}
					nackRange.FirstPacketNumber = lastNackRange.FirstPacketNumber - protocol.PacketNumber(missingPacketSequenceNumberDelta+uint64(rangeLength)) - 1
				}
				nackRange.LastPacketNumber = protocol.PacketNumber(uint64(nackRange.FirstPacketNumber) + uint64(rangeLength))
				frame.NackRanges = append(frame.NackRanges, nackRange)
			}

			// TODO: Remove once we drop support for versions <32
			if version < protocol.Version32 {
				_, err = r.ReadByte()
				if err != nil {
					return nil, err
				}
			}
		}
	}

	if !frame.validateNackRanges() {
		return nil, errInvalidNackRanges
	}

	return frame, nil
}

func (f *AckFrame) validateNackRanges() bool {
	// check the validity of every single NACK range
	for _, nackRange := range f.NackRanges {
		if nackRange.FirstPacketNumber > nackRange.LastPacketNumber {
			return false
		}
		if nackRange.LastPacketNumber > f.LargestObserved {
			return false
		}
	}

	// check the consistency for ACK with multiple NACK ranges
	for i, nackRange := range f.NackRanges {
		if i == 0 {
			continue
		}
		lastNackRange := f.NackRanges[i-1]
		if lastNackRange.FirstPacketNumber <= nackRange.FirstPacketNumber {
			return false
		}
		if lastNackRange.FirstPacketNumber <= nackRange.LastPacketNumber {
			return false
		}
	}

	return true
}
