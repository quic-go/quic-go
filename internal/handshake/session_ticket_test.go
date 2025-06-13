package handshake

import (
	"testing"

	"github.com/Noooste/uquic-go/internal/wire"
	"github.com/Noooste/uquic-go/quicvarint"

	"github.com/stretchr/testify/require"
)

func TestMarshalUnmarshalSessionTicket(t *testing.T) {
	ticket := &sessionTicket{
		Parameters: &wire.TransportParameters{
			InitialMaxStreamDataBidiLocal:  1,
			InitialMaxStreamDataBidiRemote: 2,
			ActiveConnectionIDLimit:        10,
			MaxDatagramFrameSize:           20,
		},
	}
	var t2 sessionTicket
	require.NoError(t, t2.Unmarshal(ticket.Marshal()))
	require.EqualValues(t, 1, t2.Parameters.InitialMaxStreamDataBidiLocal)
	require.EqualValues(t, 2, t2.Parameters.InitialMaxStreamDataBidiRemote)
	require.EqualValues(t, 10, t2.Parameters.ActiveConnectionIDLimit)
	require.EqualValues(t, 20, t2.Parameters.MaxDatagramFrameSize)
}

func TestUnmarshalRefusesTooShortTicket(t *testing.T) {
	err := (&sessionTicket{}).Unmarshal([]byte{})
	require.EqualError(t, err, "failed to read session ticket revision")
}

func TestUnmarshalRefusesUnknownRevision(t *testing.T) {
	b := quicvarint.Append(nil, 1337)
	err := (&sessionTicket{}).Unmarshal(b)
	require.EqualError(t, err, "unknown session ticket revision: 1337")
}

func TestUnmarshal0RTTRefusesInvalidTransportParameters(t *testing.T) {
	b := quicvarint.Append(nil, sessionTicketRevision)
	b = append(b, []byte("foobar")...)
	err := (&sessionTicket{}).Unmarshal(b)
	require.Error(t, err)
	require.Contains(t, err.Error(), "unmarshaling transport parameters from session ticket failed")
}
