package qlog

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/qlogwriter/jsontext"

	"github.com/stretchr/testify/require"
)

func checkHeader(t *testing.T, hdr *PacketHeader, expected map[string]any) {
	t.Helper()

	var buf bytes.Buffer
	enc := jsontext.NewEncoder(&buf)
	require.NoError(t, hdr.encode(enc))
	data := buf.Bytes()
	require.True(t, json.Valid(data))
	checkEncoding(t, data, expected)
}

func TestHeaderInitial(t *testing.T) {
	checkHeader(t,
		&PacketHeader{
			PacketType:   PacketTypeInitial,
			PacketNumber: 42,
			Version:      protocol.Version(0xdecafbad),
		},
		map[string]any{
			"packet_type":   "initial",
			"packet_number": 42,
			"dcil":          0,
			"scil":          0,
			"version":       "decafbad",
		},
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
		map[string]any{
			"packet_type":   "initial",
			"packet_number": 1337,
			"dcil":          4,
			"dcid":          "55667788",
			"scil":          4,
			"scid":          "11223344",
			"version":       "decafbad",
			"token":         map[string]any{"data": "deadbeef"},
		},
	)
}

func TestHeaderLongPacketNumbers(t *testing.T) {
	t.Run("packet 0", func(t *testing.T) {
		testHeaderPacketNumbers(t, 0)
	})

	// This is used for events where the packet number is not yet known,
	// e.g. the packet_buffered event.
	t.Run("no packet number", func(t *testing.T) {
		testHeaderPacketNumbers(t, 1)
	})
}

func testHeaderPacketNumbers(t *testing.T, pn protocol.PacketNumber) {
	expected := map[string]any{
		"packet_type": "handshake",
		"dcil":        0,
		"scil":        0,
		"version":     "1",
	}
	if pn != protocol.InvalidPacketNumber {
		expected["packet_number"] = int(pn)
	}
	checkHeader(t,
		&PacketHeader{
			PacketType:   PacketTypeHandshake,
			PacketNumber: pn,
			Version:      protocol.Version1,
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
		map[string]any{
			"packet_type": "retry",
			"dcil":        5,
			"dcid":        "5566778899",
			"scil":        4,
			"scid":        "11223344",
			"token":       map[string]any{"data": "deadbeef"},
			"version":     "decafbad",
		},
	)
}

func TestHeader1RTT(t *testing.T) {
	checkHeader(t,
		&PacketHeader{
			PacketType:       PacketType1RTT,
			PacketNumber:     42,
			DestConnectionID: protocol.ParseConnectionID([]byte{0x55, 0x66, 0x77, 0x88}),
			KeyPhaseBit:      KeyPhaseZero,
		},
		map[string]any{
			"packet_type":   "1RTT",
			"packet_number": 42,
			"dcil":          4,
			"dcid":          "55667788",
			"key_phase_bit": "0",
		},
	)
}
