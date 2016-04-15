package quic

import (
	"bytes"

	"github.com/lucas-clemente/quic-go/utils"
)

// An AckFrame in QUIC
type AckFrame struct {
	Entropy         byte
	LargestObserved uint64
	DelayTime       uint16 // Todo: properly interpret this value as described in the specification
}

// Write writes an ACK frame.
func (f *AckFrame) Write(b *bytes.Buffer) error {
	typeByte := uint8(0x48)
	b.WriteByte(typeByte)
	b.WriteByte(f.Entropy)
	utils.WriteUint32(b, uint32(f.LargestObserved)) // TODO: send the correct length
	utils.WriteUint16(b, 1)                         // TODO: Ack delay time
	b.WriteByte(0x01)                               // Just one timestamp
	b.WriteByte(0x00)                               // Largest observed
	utils.WriteUint32(b, 0)                         // First timestamp
	return nil
}

// ParseAckFrame reads an ACK frame
func ParseAckFrame(r *bytes.Reader) (*AckFrame, error) {
	frame := &AckFrame{}

	typeByte, err := r.ReadByte()
	if err != nil {
		return nil, err
	}

	if typeByte&0x20 == 0x20 {
		panic("NACK ranges not yet implemented.")
	}
	if typeByte&0x10 == 0x10 {
		panic("truncated ACKs not yet implemented.")
	}

	largestObservedLen := 2 * ((typeByte & 0x0C) >> 2)
	if largestObservedLen == 0 {
		largestObservedLen = 1
	}

	var missingSequenceNumberDeltaLen uint8 = 2 * (typeByte & 0x03)
	if missingSequenceNumberDeltaLen == 0 {
		missingSequenceNumberDeltaLen = 1
	}

	frame.Entropy, err = r.ReadByte()
	if err != nil {
		return nil, err
	}

	frame.LargestObserved, err = utils.ReadUintN(r, largestObservedLen)
	if err != nil {
		return nil, err
	}

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
		_, err := utils.ReadUint16(r)
		if err != nil {
			return nil, err
		}
	}

	return frame, nil
}
