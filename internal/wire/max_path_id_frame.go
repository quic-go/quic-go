package wire

import (
	"bytes"

	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/quicvarint"
)

// A MaxPathIDFrame is a MAX_PATH_ID frame
type MaxPathIDFrame struct {
	MaximumPathIdentifier uint64
}

func parseMaxPathIDFrame(r *bytes.Reader, _ protocol.Version) (*MaxPathIDFrame, error) {
	frame := &MaxPathIDFrame{}
	var err error
	frame.MaximumPathIdentifier, err = quicvarint.Read(r)
	if err != nil {
		return nil, err
	}
	return frame, nil
}

// Append appends a MAX_PATH_ID frame.
func (f *MaxPathIDFrame) Append(b []byte, _ protocol.Version) ([]byte, error) {
	b = quicvarint.Append(b, f.MaximumPathIdentifier)
	return b, nil
}

// Length of a written frame
func (f *MaxPathIDFrame) Length(_ protocol.Version) protocol.ByteCount {
	return protocol.ByteCount(quicvarint.Len(f.MaximumPathIdentifier))
}
[end of internal/wire/max_path_id_frame.go]
