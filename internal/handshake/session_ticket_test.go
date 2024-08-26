package handshake

import (
	"testing"
	"time"

	"github.com/quic-go/quic-go/internal/wire"
	"github.com/quic-go/quic-go/quicvarint"

	"github.com/stretchr/testify/require"
)

func TestMarshalUnmarshal0RTTSessionTicket(t *testing.T) {
	ticket := &sessionTicket{
		Parameters: &wire.TransportParameters{
			InitialMaxStreamDataBidiLocal:  1,
			InitialMaxStreamDataBidiRemote: 2,
			ActiveConnectionIDLimit:        10,
			MaxDatagramFrameSize:           20,
		},
		RTT: 1337 * time.Microsecond,
	}
	var t2 sessionTicket
	require.NoError(t, t2.Unmarshal(ticket.Marshal(), true))
	require.EqualValues(t, 1, t2.Parameters.InitialMaxStreamDataBidiLocal)
	require.EqualValues(t, 2, t2.Parameters.InitialMaxStreamDataBidiRemote)
	require.EqualValues(t, 10, t2.Parameters.ActiveConnectionIDLimit)
	require.EqualValues(t, 20, t2.Parameters.MaxDatagramFrameSize)
	require.Equal(t, 1337*time.Microsecond, t2.RTT)
	// fails to unmarshal the ticket as a non-0-RTT ticket
	require.Error(t, t2.Unmarshal(ticket.Marshal(), false))
	require.EqualError(t, t2.Unmarshal(ticket.Marshal(), false), "the session ticket has more bytes than expected")
}

func TestMarshalUnmarshalNon0RTTSessionTicket(t *testing.T) {
	ticket := &sessionTicket{
		RTT: 1337 * time.Microsecond,
	}
	var t2 sessionTicket
	require.NoError(t, t2.Unmarshal(ticket.Marshal(), false))
	require.Nil(t, t2.Parameters)
	require.Equal(t, 1337*time.Microsecond, t2.RTT)
	// fails to unmarshal the ticket as a 0-RTT ticket
	err := t2.Unmarshal(ticket.Marshal(), true)
	require.Error(t, err)
	require.Contains(t, err.Error(), "unmarshaling transport parameters from session ticket failed")
}

func TestUnmarshalRefusesTooShortTicket(t *testing.T) {
	err := (&sessionTicket{}).Unmarshal([]byte{}, true)
	require.EqualError(t, err, "failed to read session ticket revision")
	err = (&sessionTicket{}).Unmarshal([]byte{}, false)
	require.EqualError(t, err, "failed to read session ticket revision")
}

func TestUnmarshalRefusesUnknownRevision(t *testing.T) {
	b := quicvarint.Append(nil, 1337)
	err := (&sessionTicket{}).Unmarshal(b, true)
	require.EqualError(t, err, "unknown session ticket revision: 1337")
	err = (&sessionTicket{}).Unmarshal(b, false)
	require.EqualError(t, err, "unknown session ticket revision: 1337")
}

func TestUnmarshalRefusesInvalidRTT(t *testing.T) {
	b := quicvarint.Append(nil, sessionTicketRevision)
	err := (&sessionTicket{}).Unmarshal(b, true)
	require.EqualError(t, err, "failed to read RTT")
	err = (&sessionTicket{}).Unmarshal(b, false)
	require.EqualError(t, err, "failed to read RTT")
}

func TestUnmarshal0RTTRefusesInvalidTransportParameters(t *testing.T) {
	b := quicvarint.Append(nil, sessionTicketRevision)
	b = append(b, []byte("foobar")...)
	err := (&sessionTicket{}).Unmarshal(b, true)
	require.Error(t, err)
	require.Contains(t, err.Error(), "unmarshaling transport parameters from session ticket failed")
}

func TestUnmarshalNon0RTTRefusesExtraBytes(t *testing.T) {
	ticket := &sessionTicket{
		Parameters: &wire.TransportParameters{
			InitialMaxStreamDataBidiLocal:  1,
			InitialMaxStreamDataBidiRemote: 2,
			ActiveConnectionIDLimit:        10,
			MaxDatagramFrameSize:           20,
		},
		RTT: 1234 * time.Microsecond,
	}
	err := (&sessionTicket{}).Unmarshal(ticket.Marshal(), false)
	require.Error(t, err)
	require.Contains(t, err.Error(), "the session ticket has more bytes than expected")
}
