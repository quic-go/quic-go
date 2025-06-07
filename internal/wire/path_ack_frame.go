package wire

import (
	"bytes"
	"time"

	"github.com/quic-go/quic-go/internal/ackhandler"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/quicvarint"
)

// A PathAckFrame is a PATH_ACK frame.
// It is similar to an ACK frame, but specific to a path.
type PathAckFrame struct {
	PathIdentifier protocol.PathID
	LargestAcked   protocol.PacketNumber
	DelayTime      time.Duration
	AckRanges      []ackhandler.AckRange // Slice of ackhandler.AckRange, exported by ackhandler package
	ECNCounts      *ECNCounts            // Pointer to ECNCounts, exported by this package (wire)
}

// Length of a written frame.
func (f *PathAckFrame) Length(v protocol.Version) protocol.ByteCount {
	length := quicvarint.Len(uint64(f.PathIdentifier))
	if len(f.AckRanges) == 0 { // Should not happen with a valid ACK frame logic
		return protocol.ByteCount(length + quicvarint.Len(0) + quicvarint.Len(0) + quicvarint.Len(0))
	}
	largestAcked := f.AckRanges[0].Largest // Assuming AckRanges are sorted as in wire.AckFrame

	length += quicvarint.Len(uint64(largestAcked))
	// Note: ackDelayExponent is not used for Length calculation of the delay value itself,
	// only for encoding. The varint length depends on the magnitude of the encoded value.
	// We use the scaled value for Length calculation as that's what gets encoded.
	length += quicvarint.Len(encodeAckDelay(f.DelayTime, protocol.DefaultAckDelayExponent)) // Use default for length calculation, actual exponent for Append

	numRanges := len(f.AckRanges)
	length += quicvarint.Len(uint64(numRanges -1)) // Number of additional blocks

	// First ACK range block
	length += quicvarint.Len(uint64(f.AckRanges[0].Largest - f.AckRanges[0].Smallest))

	// Subsequent ACK range blocks
	for i := 1; i < numRanges; i++ {
		gap := uint64(f.AckRanges[i-1].Smallest - f.AckRanges[i].Largest - 2)
		ackRangeLen := uint64(f.AckRanges[i].Largest - f.AckRanges[i].Smallest)
		length += quicvarint.Len(gap)
		length += quicvarint.Len(ackRangeLen)
	}

	if f.ECNCounts != nil {
		length += quicvarint.Len(f.ECNCounts.ECT0)
		length += quicvarint.Len(f.ECNCounts.ECT1)
		length += quicvarint.Len(f.ECNCounts.CE)
	}
	return protocol.ByteCount(length)
}

// Append appends a PATH_ACK frame.
// The ackDelayExponent is the one negotiated for 1-RTT packets.
func (f *PathAckFrame) Append(b []byte, ackDelayExponent uint8, v protocol.Version) ([]byte, error) {
	b = quicvarint.Append(b, uint64(f.PathIdentifier))

	if len(f.AckRanges) == 0 {
		// This case should ideally be prevented by higher-level logic
		// (e.g., an ACK frame must acknowledge at least one packet).
		// However, to be safe, append default values if it occurs.
		b = quicvarint.Append(b, 0) // Largest Acked
		b = quicvarint.Append(b, 0) // ACK Delay
		b = quicvarint.Append(b, 0) // Num ACK Ranges - 1
		// No ranges to append.
		// No ECN counts if there are no ranges.
		return b, nil
	}

	// Sort AckRanges to ensure Largest is first, and then by Largest descending.
	// This is critical for correct gap encoding. The wire.AckFrame does this.
	// For PathAckFrame, we assume it's already sorted by the caller (e.g. path specific ack handler).
	// If not, it needs sorting here:
	// sort.Slice(f.AckRanges, func(i, j int) bool {
	//    return f.AckRanges[i].Largest > f.AckRanges[j].Largest
	// })

	b = quicvarint.Append(b, uint64(f.AckRanges[0].Largest))
	b = quicvarint.Append(b, encodeAckDelay(f.DelayTime, ackDelayExponent))

	numRanges := len(f.AckRanges)
	b = quicvarint.Append(b, uint64(numRanges-1)) // Number of additional blocks

	// First ACK range block: Largest Acked - Smallest Acked in this block
	b = quicvarint.Append(b, uint64(f.AckRanges[0].Largest-f.AckRanges[0].Smallest))

	// Subsequent ACK range blocks
	for i := 1; i < numRanges; i++ {
		gap := uint64(f.AckRanges[i-1].Smallest - f.AckRanges[i].Largest - 2)
		ackRangeLen := uint64(f.AckRanges[i].Largest - f.AckRanges[i].Smallest)
		b = quicvarint.Append(b, gap)
		b = quicvarint.Append(b, ackRangeLen)
	}

	if f.ECNCounts != nil {
		b = quicvarint.Append(b, f.ECNCounts.ECT0)
		b = quicvarint.Append(b, f.ECNCounts.ECT1)
		b = quicvarint.Append(b, f.ECNCounts.CE)
	}
	return b, nil
}

// parsePathAckFrame parses a PATH_ACK frame.
// It's similar to parseAckFrameBody but includes a PathIdentifier.
func parsePathAckFrame(r *bytes.Reader, frameType uint8, ackDelayExponent uint8, _ protocol.Version) (*PathAckFrame, error) {
	frame := &PathAckFrame{}

	pathID, err := quicvarint.Read(r)
	if err != nil {
		return nil, err
	}
	frame.PathIdentifier = protocol.PathID(pathID)

	// The rest of the parsing is similar to ackFrame.parseBody
	largestAcked, err := quicvarint.Read(r)
	if err != nil {
		return nil, err
	}
	frame.LargestAcked = protocol.PacketNumber(largestAcked)

	delayTime, err := quicvarint.Read(r)
	if err != nil {
		return nil, err
	}
	frame.DelayTime = time.Duration(delayTime) * time.Microsecond
	if frame.DelayTime > protocol.MaxAckDelay { // Apply ack delay exponent if it's a 1-RTT ACK
		frame.DelayTime <<= ackDelayExponent
	}


	numBlocks, err := quicvarint.Read(r)
	if err != nil {
		return nil, err
	}

	// ACK Ranges
	if numBlocks > 0 {
		frame.AckRanges = make([]ackhandler.AckRange, 0, numBlocks)
		// First ACK range
		firstAckRangeLen, err := quicvarint.Read(r)
		if err != nil {
			return nil, err
		}
		if protocol.PacketNumber(firstAckRangeLen) > frame.LargestAcked {
			return nil, errInvalidAckRanges
		}
		frame.AckRanges = append(frame.AckRanges, ackhandler.AckRange{
			Smallest: frame.LargestAcked - protocol.PacketNumber(firstAckRangeLen),
			Largest:  frame.LargestAcked,
		})

		// Subsequent ACK ranges
		for i := uint64(0); i < numBlocks; i++ {
			gap, err := quicvarint.Read(r)
			if err != nil {
				return nil, err
			}
			ackRangeLen, err := quicvarint.Read(r)
			if err != nil {
				return nil, err
			}

			lastRange := frame.AckRanges[len(frame.AckRanges)-1]
			if protocol.PacketNumber(gap+2) > lastRange.Smallest { // check for underflow
                 return nil, errInvalidAckRanges
            }
			smallest := lastRange.Smallest - protocol.PacketNumber(gap) - 2
			if protocol.PacketNumber(ackRangeLen) > smallest { // check for underflow
                 return nil, errInvalidAckRanges
            }
			largest := smallest + protocol.PacketNumber(ackRangeLen)
			frame.AckRanges = append(frame.AckRanges, ackhandler.AckRange{Smallest: smallest, Largest: largest})
		}
	}


	// ECN Counts (if this is a PATH_ACK_ECN frame type)
	if frameType == PathAckWithECNFrameType { // Assuming PathAckWithECNFrameType is defined elsewhere
		frame.ECNCounts = &ECNCounts{}
		frame.ECNCounts.ECT0, err = quicvarint.Read(r)
		if err != nil {
			return nil, err
		}
		frame.ECNCounts.ECT1, err = quicvarint.Read(r)
		if err != nil {
			return nil, err
		}
		frame.ECNCounts.CE, err = quicvarint.Read(r)
		if err != nil {
			return nil, err
		}
	}

	if r.Len() != 0 {
		return nil, errRemainingBytes
	}
	return frame, nil
}

// encodeAckDelay encodes the ACK Delay
func encodeAckDelay(delay time.Duration, ackDelayExponent uint8) uint64 {
	return uint64(delay.Nanoseconds() / (1000 * (1 << ackDelayExponent)))
}
[end of internal/wire/path_ack_frame.go]
