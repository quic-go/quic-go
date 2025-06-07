package wire

import (
	"bytes"

	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/quicvarint"
)

// A PathCIDsBlockedFrame is a PATH_CIDS_BLOCKED frame
type PathCIDsBlockedFrame struct {
	PathIdentifier     protocol.PathID
	NextSequenceNumber uint64 // Sequence number of the CID that would have been offered
}

func parsePathCIDsBlockedFrame(r *bytes.Reader, _ protocol.Version) (*PathCIDsBlockedFrame, error) {
	frame := &PathCIDsBlockedFrame{}

	pathID, err := quicvarint.Read(r)
	if err != nil {
		return nil, err
	}
	frame.PathIdentifier = protocol.PathID(pathID)

	frame.NextSequenceNumber, err = quicvarint.Read(r)
	if err != nil {
		return nil, err
	}
	return frame, nil
}

// Append appends a PATH_CIDS_BLOCKED frame.
func (f *PathCIDsBlockedFrame) Append(b []byte, _ protocol.Version) ([]byte, error) {
	b = quicvarint.Append(b, uint64(f.PathIdentifier))
	b = quicvarint.Append(b, f.NextSequenceNumber)
	return b, nil
}

// Length of a written frame
func (f *PathCIDsBlockedFrame) Length(_ protocol.Version) protocol.ByteCount {
	return protocol.ByteCount(quicvarint.Len(uint64(f.PathIdentifier))) +
		quicvarint.Len(f.NextSequenceNumber)
}
[end of internal/wire/path_cids_blocked_frame.go]
