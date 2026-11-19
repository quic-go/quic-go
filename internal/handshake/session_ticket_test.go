package handshake

import (
	"encoding/binary"
	"testing"

	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/wire"
	"github.com/quic-go/quic-go/quicvarint"

	"github.com/stretchr/testify/require"
)

func TestMarshalUnmarshalSessionTicket(t *testing.T) {
	ticket := &sessionTicket{
		Version: protocol.Version2,
		Parameters: &wire.TransportParameters{
			InitialMaxStreamDataBidiLocal:  1,
			InitialMaxStreamDataBidiRemote: 2,
			ActiveConnectionIDLimit:        10,
			MaxDatagramFrameSize:           20,
		},
	}
	var t2 sessionTicket
	require.NoError(t, t2.Unmarshal(ticket.Marshal()))
	require.Equal(t, protocol.Version2, t2.Version)
	require.EqualValues(t, 1, t2.Parameters.InitialMaxStreamDataBidiLocal)
	require.EqualValues(t, 2, t2.Parameters.InitialMaxStreamDataBidiRemote)
	require.EqualValues(t, 10, t2.Parameters.ActiveConnectionIDLimit)
	require.EqualValues(t, 20, t2.Parameters.MaxDatagramFrameSize)
}

func TestUnmarshalRefusesTooShortTicket(t *testing.T) {
	err := (&sessionTicket{}).Unmarshal([]byte{0, 0, 1})
	require.EqualError(t, err, "failed to read session ticket version")
	err = (&sessionTicket{}).Unmarshal(binary.BigEndian.AppendUint32(nil, uint32(protocol.Version1)))
	require.EqualError(t, err, "failed to read session ticket revision")
}

func TestUnmarshalRefusesUnknownRevision(t *testing.T) {
	b := binary.BigEndian.AppendUint32(nil, uint32(protocol.Version1))
	b = quicvarint.Append(b, 1337)
	err := (&sessionTicket{}).Unmarshal(b)
	require.EqualError(t, err, "unknown session ticket revision: 1337")
}

func TestUnmarshal0RTTRefusesInvalidTransportParameters(t *testing.T) {
	b := binary.BigEndian.AppendUint32(nil, uint32(protocol.Version1))
	b = quicvarint.Append(b, sessionTicketRevision)
	b = append(b, []byte("foobar")...)
	err := (&sessionTicket{}).Unmarshal(b)
	require.ErrorContains(t, err, "unmarshaling transport parameters from session ticket failed")
}
