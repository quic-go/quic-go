package qlog

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/Noooste/quic-go/internal/protocol"
	"github.com/Noooste/quic-go/internal/wire"
	"github.com/Noooste/quic-go/logging"
	"github.com/francoispqt/gojay"
	"github.com/stretchr/testify/require"
)

func TestPacketTypeFromEncryptionLevel(t *testing.T) {
	tests := []struct {
		name  string
		level protocol.EncryptionLevel
		want  logging.PacketType
	}{
		{"Initial", protocol.EncryptionInitial, logging.PacketTypeInitial},
		{"Handshake", protocol.EncryptionHandshake, logging.PacketTypeHandshake},
		{"0-RTT", protocol.Encryption0RTT, logging.PacketType0RTT},
		{"1-RTT", protocol.Encryption1RTT, logging.PacketType1RTT},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := getPacketTypeFromEncryptionLevel(tt.level)
			require.Equal(t, tt.want, got)
		})
	}
}

func checkHeader(t *testing.T, hdr *wire.ExtendedHeader, expected map[string]interface{}) {
	buf := &bytes.Buffer{}
	enc := gojay.NewEncoder(buf)
	require.NoError(t, enc.Encode(transformLongHeader(hdr)))
	data := buf.Bytes()
	require.True(t, json.Valid(data))
	checkEncoding(t, data, expected)
}

func TestMarshalHeaderWithPayloadLength(t *testing.T) {
	checkHeader(t,
		&wire.ExtendedHeader{
			PacketNumber: 42,
			Header: wire.Header{
				Type:    protocol.PacketTypeInitial,
				Length:  123,
				Version: protocol.Version(0xdecafbad),
			},
		},
		map[string]interface{}{
			"packet_type":   "initial",
			"packet_number": 42,
			"dcil":          0,
			"scil":          0,
			"version":       "decafbad",
		},
	)
}

func TestMarshalInitialWithToken(t *testing.T) {
	checkHeader(t,
		&wire.ExtendedHeader{
			PacketNumber: 4242,
			Header: wire.Header{
				Type:    protocol.PacketTypeInitial,
				Length:  123,
				Version: protocol.Version(0xdecafbad),
				Token:   []byte{0xde, 0xad, 0xbe, 0xef},
			},
		},
		map[string]interface{}{
			"packet_type":   "initial",
			"packet_number": 4242,
			"dcil":          0,
			"scil":          0,
			"version":       "decafbad",
			"token":         map[string]interface{}{"data": "deadbeef"},
		},
	)
}

func TestMarshalRetryPacket(t *testing.T) {
	checkHeader(t,
		&wire.ExtendedHeader{
			Header: wire.Header{
				Type:            protocol.PacketTypeRetry,
				SrcConnectionID: protocol.ParseConnectionID([]byte{0x11, 0x22, 0x33, 0x44}),
				Version:         protocol.Version(0xdecafbad),
				Token:           []byte{0xde, 0xad, 0xbe, 0xef},
			},
		},
		map[string]interface{}{
			"packet_type": "retry",
			"dcil":        0,
			"scil":        4,
			"scid":        "11223344",
			"token":       map[string]interface{}{"data": "deadbeef"},
			"version":     "decafbad",
		},
	)
}

func TestMarshalPacketWithPacketNumber0(t *testing.T) {
	checkHeader(t,
		&wire.ExtendedHeader{
			PacketNumber: 0,
			Header: wire.Header{
				Type:    protocol.PacketTypeHandshake,
				Version: protocol.Version(0xdecafbad),
			},
		},
		map[string]interface{}{
			"packet_type":   "handshake",
			"packet_number": 0,
			"dcil":          0,
			"scil":          0,
			"version":       "decafbad",
		},
	)
}

func TestMarshalHeaderWithSourceConnectionID(t *testing.T) {
	checkHeader(t,
		&wire.ExtendedHeader{
			PacketNumber: 42,
			Header: wire.Header{
				Type:            protocol.PacketTypeHandshake,
				SrcConnectionID: protocol.ParseConnectionID([]byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}),
				Version:         protocol.Version(0xdecafbad),
			},
		},
		map[string]interface{}{
			"packet_type":   "handshake",
			"packet_number": 42,
			"dcil":          0,
			"scil":          16,
			"scid":          "00112233445566778899aabbccddeeff",
			"version":       "decafbad",
		},
	)
}
