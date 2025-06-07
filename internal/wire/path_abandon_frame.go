package wire

import (
	"bytes"

	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/quicvarint"
)

// A PathAbandonFrame is a PATH_ABANDON frame
type PathAbandonFrame struct {
	PathIdentifier protocol.PathID
	ErrorCode      uint64 // Using uint64 for generality as per multipath draft, maps to qerr.TransportErrorCode
}

func parsePathAbandonFrame(r *bytes.Reader, _ protocol.Version) (*PathAbandonFrame, error) {
	frame := &PathAbandonFrame{}

	pathID, err := quicvarint.Read(r)
	if err != nil {
		return nil, err
	}
	frame.PathIdentifier = protocol.PathID(pathID)

	frame.ErrorCode, err = quicvarint.Read(r)
	if err != nil {
		return nil, err
	}
	return frame, nil
}

// Append appends a PATH_ABANDON frame.
func (f *PathAbandonFrame) Append(b []byte, _ protocol.Version) ([]byte, error) {
	b = quicvarint.Append(b, uint64(f.PathIdentifier))
	b = quicvarint.Append(b, f.ErrorCode)
	return b, nil
}

// Length of a written frame
func (f *PathAbandonFrame) Length(_ protocol.Version) protocol.ByteCount {
	return protocol.ByteCount(quicvarint.Len(uint64(f.PathIdentifier))) +
		quicvarint.Len(f.ErrorCode)
}
[end of internal/wire/path_abandon_frame.go]
