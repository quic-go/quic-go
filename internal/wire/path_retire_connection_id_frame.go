package wire

import (
	"bytes"

	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/quicvarint"
)

// A PathRetireConnectionIDFrame is a PATH_RETIRE_CONNECTION_ID frame
type PathRetireConnectionIDFrame struct {
	PathIdentifier protocol.PathID
	SequenceNumber uint64
}

func parsePathRetireConnectionIDFrame(r *bytes.Reader, _ protocol.Version) (*PathRetireConnectionIDFrame, error) {
	frame := &PathRetireConnectionIDFrame{}

	pathID, err := quicvarint.Read(r)
	if err != nil {
		return nil, err
	}
	frame.PathIdentifier = protocol.PathID(pathID)

	frame.SequenceNumber, err = quicvarint.Read(r)
	if err != nil {
		return nil, err
	}
	return frame, nil
}

// Append appends a PATH_RETIRE_CONNECTION_ID frame.
func (f *PathRetireConnectionIDFrame) Append(b []byte, _ protocol.Version) ([]byte, error) {
	b = quicvarint.Append(b, uint64(f.PathIdentifier))
	b = quicvarint.Append(b, f.SequenceNumber)
	return b, nil
}

// Length of a written frame
func (f *PathRetireConnectionIDFrame) Length(_ protocol.Version) protocol.ByteCount {
	return protocol.ByteCount(quicvarint.Len(uint64(f.PathIdentifier))) +
		quicvarint.Len(f.SequenceNumber)
}
[end of internal/wire/path_retire_connection_id_frame.go]
