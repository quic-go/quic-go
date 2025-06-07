package wire

import (
	"bytes"

	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/quicvarint"
)

// A PathBackupFrame is a PATH_BACKUP frame
type PathBackupFrame struct {
	PathIdentifier           protocol.PathID
	PathStatusSequenceNumber uint64
}

func parsePathBackupFrame(r *bytes.Reader, _ protocol.Version) (*PathBackupFrame, error) {
	frame := &PathBackupFrame{}

	pathID, err := quicvarint.Read(r)
	if err != nil {
		return nil, err
	}
	frame.PathIdentifier = protocol.PathID(pathID)

	frame.PathStatusSequenceNumber, err = quicvarint.Read(r)
	if err != nil {
		return nil, err
	}
	return frame, nil
}

// Append appends a PATH_BACKUP frame.
func (f *PathBackupFrame) Append(b []byte, _ protocol.Version) ([]byte, error) {
	b = quicvarint.Append(b, uint64(f.PathIdentifier))
	b = quicvarint.Append(b, f.PathStatusSequenceNumber)
	return b, nil
}

// Length of a written frame
func (f *PathBackupFrame) Length(_ protocol.Version) protocol.ByteCount {
	return protocol.ByteCount(quicvarint.Len(uint64(f.PathIdentifier))) +
		quicvarint.Len(f.PathStatusSequenceNumber)
}
[end of internal/wire/path_backup_frame.go]
