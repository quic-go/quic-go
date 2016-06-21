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

	hasMissingRanges := false
	if typeByte&0x20 == 0x20 {
		hasMissingRanges = true
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
	if hasMissingRanges {
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

	if hasMissingRanges {
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

	if !frame.validateAckRanges() {
		return nil, errInvalidAckRanges
	}

	var numTimestampByte byte
	numTimestampByte, err = r.ReadByte()
	if err != nil {
		return nil, err
	}
	numTimestamp := uint8(numTimestampByte)

	if numTimestamp > 0 {
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

	return frame, nil
}

// Write writes an ACK frame.
func (f *AckFrameNew) Write(b *bytes.Buffer, version protocol.VersionNumber) error {
	largestObservedLen := protocol.GetPacketNumberLength(f.LargestObserved)

	typeByte := uint8(0x40)

	if largestObservedLen != protocol.PacketNumberLen1 {
		typeByte ^= (uint8(largestObservedLen / 2)) << 2
	}

	// TODO: send shorter values, if possible
	missingSequenceNumberDeltaLen := protocol.PacketNumberLen6
	if missingSequenceNumberDeltaLen != protocol.PacketNumberLen1 {
		typeByte ^= (uint8(missingSequenceNumberDeltaLen / 2))
	}

	if f.HasMissingRanges() {
		typeByte |= (0x20 | 0x03)
	}

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

	f.DelayTime = time.Now().Sub(f.PacketReceivedTime)
	utils.WriteUfloat16(b, uint64(f.DelayTime/time.Microsecond))

	var numRanges uint64
	var numRangesWritten uint64 // to check for internal consistency
	if f.HasMissingRanges() {
		numRanges = f.numWrittenNackRanges()
		if numRanges >= 0xFF {
			panic("AckFrame: Too many ACK ranges")
		}
		b.WriteByte(uint8(numRanges - 1))
	}

	if !f.HasMissingRanges() {
		utils.WriteUint48(b, uint64(f.LargestObserved-f.LowestAcked))
	} else {
		if f.LargestObserved != f.AckRanges[0].LastPacketNumber {
			return errors.New("internal inconsistency")
		}
		length := f.LargestObserved - f.AckRanges[0].FirstPacketNumber + 1
		utils.WriteUint48(b, uint64(length))
		numRangesWritten++
	}

	for i, ackRange := range f.AckRanges {
		if i == 0 {
			continue
		}

		length := ackRange.LastPacketNumber - ackRange.FirstPacketNumber + 1
		gap := f.AckRanges[i-1].FirstPacketNumber - ackRange.LastPacketNumber - 1

		num := gap/0xFF + 1
		if gap%0xFF == 0 {
			num--
		}

		if num == 1 {
			b.WriteByte(uint8(gap))
			utils.WriteUint48(b, uint64(length))
			numRangesWritten++
		} else {
			for i := 0; i < int(num); i++ {
				var lengthWritten uint64
				var gapWritten uint8

				if i == int(num)-1 { // last block
					lengthWritten = uint64(length)
					gapWritten = uint8(gap % 0xFF)
				} else {
					lengthWritten = 0
					gapWritten = 0xFF
				}

				b.WriteByte(uint8(gapWritten))
				utils.WriteUint48(b, lengthWritten)
				numRangesWritten++
			}
		}
	}

	if numRanges != numRangesWritten {
		return errors.New("BUG: Inconsistent number of ACK ranges written")
	}

	b.WriteByte(0) // no timestamps

	return nil
}

// MinLength of a written frame
func (f *AckFrameNew) MinLength(version protocol.VersionNumber) (protocol.ByteCount, error) {
	var length protocol.ByteCount
	length = 1 + 2 + 1 // 1 TypeByte, 2 ACK delay time, 1 Num Timestamp
	length += protocol.ByteCount(protocol.GetPacketNumberLength(f.LargestObserved))

	missingSequenceNumberDeltaLen := protocol.ByteCount(protocol.PacketNumberLen6)

	if f.HasMissingRanges() {
		length += (1 + missingSequenceNumberDeltaLen) * protocol.ByteCount(f.numWrittenNackRanges())
	} else {
		length += missingSequenceNumberDeltaLen
	}

	length += (1 + 2) * 0 /* TODO: num_timestamps */

	return length, nil
}

// HasMissingRanges returns if this frame reports any missing packets
func (f *AckFrameNew) HasMissingRanges() bool {
	if len(f.AckRanges) > 0 {
		return true
	}
	return false
}

// GetHighestInOrderPacketNumber gets the highest in order packet number that is confirmed by this ACK
func (f *AckFrameNew) GetHighestInOrderPacketNumber() protocol.PacketNumber {
	if f.HasMissingRanges() {
		panic("NACKs not yet implemented")
	}
	return f.LargestObserved
}

func (f *AckFrameNew) validateAckRanges() bool {
	if len(f.AckRanges) == 0 {
		return true
	}

	// if there are missing packets, there will always be at least 2 ACK ranges
	if len(f.AckRanges) == 1 {
		return false
	}

	if f.AckRanges[0].LastPacketNumber != f.LargestObserved {
		return false
	}

	// check the validity of every single ACK range
	for _, ackRange := range f.AckRanges {
		if ackRange.FirstPacketNumber > ackRange.LastPacketNumber {
			return false
		}
	}

	// check the consistency for ACK with multiple NACK ranges
	for i, ackRange := range f.AckRanges {
		if i == 0 {
			continue
		}
		lastAckRange := f.AckRanges[i-1]
		if lastAckRange.FirstPacketNumber <= ackRange.FirstPacketNumber {
			return false
		}
		if lastAckRange.FirstPacketNumber <= ackRange.LastPacketNumber+1 {
			return false
		}
	}

	return true
}

// numWrittenNackRanges calculates the number of ACK blocks that are about to be written
// this number is different from len(f.AckRanges) for the case of long gaps (> 255 packets)
func (f *AckFrameNew) numWrittenNackRanges() uint64 {
	if len(f.AckRanges) == 0 {
		return 0
	}

	var numRanges uint64
	for i, ackRange := range f.AckRanges {
		if i == 0 {
			continue
		}

		lastAckRange := f.AckRanges[i-1]
		gap := lastAckRange.FirstPacketNumber - ackRange.LastPacketNumber
		numRanges += 1 + uint64(gap)/(0xFF+1)
		if uint64(gap)%(0xFF+1) == 0 {
			numRanges--
		}
	}

	return numRanges + 1
}
