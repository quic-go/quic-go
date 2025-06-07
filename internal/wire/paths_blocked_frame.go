package wire

import (
	"bytes"

	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/quicvarint"
)

// A PathsBlockedFrame is a PATHS_BLOCKED frame
type PathsBlockedFrame struct {
	MaximumPathIdentifier uint64
}

func parsePathsBlockedFrame(r *bytes.Reader, _ protocol.Version) (*PathsBlockedFrame, error) {
	frame := &PathsBlockedFrame{}
	var err error
	frame.MaximumPathIdentifier, err = quicvarint.Read(r)
	if err != nil {
		return nil, err
	}
	return frame, nil
}

// Append appends a PATHS_BLOCKED frame.
func (f *PathsBlockedFrame) Append(b []byte, _ protocol.Version) ([]byte, error) {
	b = quicvarint.Append(b, f.MaximumPathIdentifier)
	return b, nil
}

// Length of a written frame
func (f *PathsBlockedFrame) Length(_ protocol.Version) protocol.ByteCount {
	return protocol.ByteCount(quicvarint.Len(f.MaximumPathIdentifier))
}
[end of internal/wire/paths_blocked_frame.go]
