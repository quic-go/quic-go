package wire

import (
	"bytes"
	"fmt"

	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/quicvarint"
)

// A PathNewConnectionIDFrame is a PATH_NEW_CONNECTION_ID frame
type PathNewConnectionIDFrame struct {
	PathIdentifier      protocol.PathID
	SequenceNumber      uint64
	RetirePriorTo       uint64
	ConnectionID        protocol.ConnectionID
	StatelessResetToken protocol.StatelessResetToken
}

func parsePathNewConnectionIDFrame(r *bytes.Reader, _ protocol.Version) (*PathNewConnectionIDFrame, error) {
	frame := &PathNewConnectionIDFrame{}

	pathID, err := quicvarint.Read(r)
	if err != nil {
		return nil, err
	}
	frame.PathIdentifier = protocol.PathID(pathID)

	frame.SequenceNumber, err = quicvarint.Read(r)
	if err != nil {
		return nil, err
	}
	frame.RetirePriorTo, err = quicvarint.Read(r)
	if err != nil {
		return nil, err
	}
	if frame.RetirePriorTo > frame.SequenceNumber {
		return nil, fmt.Errorf("RetirePriorTo (%d) greater than SequenceNumber (%d)", frame.RetirePriorTo, frame.SequenceNumber)
	}
	connIDLenByte, err := r.ReadByte()
	if err != nil {
		return nil, err
	}
	connIDLen := int(connIDLenByte)
	if connIDLen < 1 || connIDLen > protocol.MaxConnIDLen {
		return nil, fmt.Errorf("invalid connection ID length: %d", connIDLen)
	}
	frame.ConnectionID, err = protocol.ReadConnectionID(r, connIDLen)
	if err != nil {
		return nil, err
	}
	if _, err := r.Read(frame.StatelessResetToken[:]); err != nil {
		return nil, err
	}
	return frame, nil
}

// Append appends a PATH_NEW_CONNECTION_ID frame.
func (f *PathNewConnectionIDFrame) Append(b []byte, _ protocol.Version) ([]byte, error) {
	b = quicvarint.Append(b, uint64(f.PathIdentifier))
	b = quicvarint.Append(b, f.SequenceNumber)
	b = quicvarint.Append(b, f.RetirePriorTo)
	b = append(b, byte(f.ConnectionID.Len()))
	b = append(b, f.ConnectionID.Bytes()...)
	b = append(b, f.StatelessResetToken[:]...)
	return b, nil
}

// Length of a written frame
func (f *PathNewConnectionIDFrame) Length(_ protocol.Version) protocol.ByteCount {
	return protocol.ByteCount(quicvarint.Len(uint64(f.PathIdentifier))) +
		quicvarint.Len(f.SequenceNumber) +
		quicvarint.Len(f.RetirePriorTo) +
		1 /* len */ + protocol.ByteCount(f.ConnectionID.Len()) +
		16 /* stateless reset token */
}
[end of internal/wire/path_new_connection_id_frame.go]
