package qlog

import (
	"bytes"
	"testing"

	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/qlogwriter/jsontext"

	"github.com/stretchr/testify/require"
)

func checkHeader(t *testing.T, hdr *PacketHeader, expected string) {
	t.Helper()

	var buf bytes.Buffer
	enc := jsontext.NewEncoder(&buf)
	require.NoError(t, hdr.encode(enc))
	require.JSONEq(t, expected, buf.String())
}

func TestHeaderUnknownPacketType(t *testing.T) {
	checkHeader(t, &PacketHeader{DestConnectionID: OmitConnectionID, SrcConnectionID: OmitConnectionID}, `{"packet_type":"unknown"}`)
	checkHeader(t, &PacketHeader{PacketType: PacketTypeUnknown, DestConnectionID: OmitConnectionID, SrcConnectionID: OmitConnectionID}, `{"packet_type":"unknown"}`)
}

func TestHeaderInitial(t *testing.T) {
	checkHeader(t,
		&PacketHeader{
			PacketType:       PacketTypeInitial,
			PacketNumber:     42,
			Version:          protocol.Version(0xdecafbad),
			DestConnectionID: OmitConnectionID,
			SrcConnectionID:  OmitConnectionID,
		},
		`{
			"packet_type": "initial",
			"packet_number": 42,
			"version": "decafbad"
		}`,
	)
}

func TestHeaderInitialWithToken(t *testing.T) {
	checkHeader(t,
		&PacketHeader{
			PacketType:       PacketTypeInitial,
			PacketNumber:     1337,
			SrcConnectionID:  protocol.ParseConnectionID([]byte{0x11, 0x22, 0x33, 0x44}),
			DestConnectionID: protocol.ParseConnectionID([]byte{0x55, 0x66, 0x77, 0x88}),
			Version:          protocol.Version(0xdecafbad),
			Token:            &Token{Raw: []byte{0xde, 0xad, 0xbe, 0xef}},
		},
		`{
			"packet_type": "initial",
			"packet_number": 1337,
			"dcid": "55667788",
			"scid": "11223344",
			"version": "decafbad",
			"token": {"raw": {"data": "deadbeef"}}
		}`,
	)
}

func TestHeaderLongPacketNumbers(t *testing.T) {
	t.Run("packet 0", func(t *testing.T) {
		testHeaderPacketNumbers(t,
			0,
			`{
				"packet_type": "handshake",
				"packet_number": 0,
				"version": "1"
			}`,
		)
	})

	// This is used for events where the packet number is not yet known,
	// e.g. the packet_buffered event.
	t.Run("no packet number", func(t *testing.T) {
		testHeaderPacketNumbers(t,
			protocol.InvalidPacketNumber,
			`{
				"packet_type": "handshake",
				"version": "1"
			}`,
		)
	})
}

func testHeaderPacketNumbers(t *testing.T, pn protocol.PacketNumber, expected string) {
	checkHeader(t,
		&PacketHeader{
			PacketType:       PacketTypeHandshake,
			PacketNumber:     pn,
			Version:          protocol.Version1,
			DestConnectionID: OmitConnectionID,
			SrcConnectionID:  OmitConnectionID,
		},
		expected,
	)
}

func TestHeaderRetry(t *testing.T) {
	checkHeader(t,
		&PacketHeader{
			PacketType:       PacketTypeRetry,
			SrcConnectionID:  protocol.ParseConnectionID([]byte{0x11, 0x22, 0x33, 0x44}),
			DestConnectionID: protocol.ParseConnectionID([]byte{0x55, 0x66, 0x77, 0x88, 0x99}),
			Version:          protocol.Version(0xdecafbad),
			Token:            &Token{Raw: []byte{0xde, 0xad, 0xbe, 0xef}},
		},
		`{
			"packet_type": "retry",
			"dcid": "5566778899",
			"scid": "11223344",
			"token": {"raw": {"data": "deadbeef"}},
			"version": "decafbad"
		}`,
	)
}

func TestHeader1RTT(t *testing.T) {
	checkHeader(t,
		&PacketHeader{
			PacketType:       PacketType1RTT,
			PacketNumber:     42,
			DestConnectionID: protocol.ParseConnectionID([]byte{0x55, 0x66, 0x77, 0x88}),
			KeyPhaseBit:      KeyPhaseOne,
		},
		`{
			"packet_type": "1RTT",
			"packet_number": 42,
			"dcid": "55667788",
			"key_phase_bit": true
		}`,
	)
}

func TestHeaderZeroLengthConnectionIDs(t *testing.T) {
	checkHeader(t,
		&PacketHeader{
			PacketType:   PacketTypeHandshake,
			PacketNumber: 42,
			Version:      protocol.Version(0xdecafbad),
		},
		`{
			"packet_type": "handshake",
			"packet_number": 42,
			"scid": "",
			"dcid": "",
			"version": "decafbad"
		}`,
	)
}
