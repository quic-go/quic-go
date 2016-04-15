package quic

import (
	"bytes"
	"fmt"

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
func ParseAckFrame(r *bytes.Reader, typeByte byte) (*AckFrame, error) {
	frame := &AckFrame{}

	fmt.Printf("Bytes remaining in this packet: %d\n", r.Len())

	if typeByte&0x20 == 0x20 {
		panic("NACK ranges not yet implemented.")
	}
	if typeByte&0x20 == 0x20 {
		panic("truncated ACKs not yet implemented.")
	}

	largestObservedLen := 2 * ((typeByte & 0x0C) >> 2)
	if largestObservedLen == 0 {
		largestObservedLen = 1
	}

	missingSequenceNumberDeltaLen := 2 * (typeByte & 0x11)
	if missingSequenceNumberDeltaLen == 0 {
		missingSequenceNumberDeltaLen = 1
	}

	var err error
	frame.Entropy, err = r.ReadByte() // read 1
	if err != nil {
		return nil, err
	}

	frame.LargestObserved, err = utils.ReadUintN(r, largestObservedLen) // read 1
	if err != nil {
		return nil, err
	}

	frame.DelayTime, err = utils.ReadUint16(r) // read 2
	if err != nil {
		return nil, err
	}

	numTimestampByte, err := r.ReadByte() // read 1
	if err != nil {
		return nil, err
	}
	numTimestamp := uint8(numTimestampByte)
	fmt.Printf("\tnumTimestamp: %d\n", numTimestamp)

	// 1 byte Delta Largest observed
	_, err = r.ReadByte() // read 1
	if err != nil {
		return nil, err
	}
	// 4 byte First timestamp
	firstTimestamp, err := utils.ReadUint32(r) // read 4
	if err != nil {
		return nil, err
	}
	fmt.Printf("\tfirstTimestamp: %d\n", firstTimestamp)

	for i := 0; i < int(numTimestamp)-1; i++ { // ToDo: check number of repititions
		fmt.Printf("\tTimestamp #%d\n", i+2)
		// 1 byte Delta Largest observed
		_, err = r.ReadByte()
		if err != nil {
			return nil, err
		}
		// 2 byte Time Since Previous Timestamp
		timeSincePreviousTimestamp, err := utils.ReadUint16(r)
		if err != nil {
			return nil, err
		}
		fmt.Printf("\t\ttimeSincePreviousTimestamp: %d\n", timeSincePreviousTimestamp)
	}
	fmt.Printf("Bytes remaining in this packet: %d\n", r.Len())

	return frame, nil
}
