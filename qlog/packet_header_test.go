package qlog

import (
	"bytes"
	"encoding/json"

	"github.com/francoispqt/gojay"
	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/wire"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Packet Header", func() {
	check := func(hdr *wire.ExtendedHeader, expected map[string]interface{}) {
		buf := &bytes.Buffer{}
		enc := gojay.NewEncoder(buf)
		ExpectWithOffset(1, enc.Encode(transformHeader(hdr))).To(Succeed())
		data := buf.Bytes()
		ExpectWithOffset(1, json.Valid(data)).To(BeTrue())
		checkEncoding(data, expected)
	}

	It("marshals a header", func() {
		check(
			&wire.ExtendedHeader{PacketNumber: 42},
			map[string]interface{}{
				"packet_number": "42",
			},
		)
	})

	It("marshals a header with a payload length", func() {
		check(
			&wire.ExtendedHeader{
				PacketNumber: 42,
				Header:       wire.Header{Length: 123},
			},
			map[string]interface{}{
				"packet_number":  "42",
				"payload_length": 123,
			},
		)
	})

	It("marshals a header with a source connection ID", func() {
		check(
			&wire.ExtendedHeader{
				PacketNumber: 42,
				Header: wire.Header{
					SrcConnectionID: protocol.ConnectionID{0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff},
				},
			},
			map[string]interface{}{
				"packet_number": "42",
				"scil":          "16",
				"scid":          "00112233445566778899aabbccddeeff",
			},
		)
	})

	It("marshals a header with a destination connection ID", func() {
		check(
			&wire.ExtendedHeader{
				PacketNumber: 42,
				Header:       wire.Header{DestConnectionID: protocol.ConnectionID{0xde, 0xad, 0xbe, 0xef}},
			},
			map[string]interface{}{
				"packet_number": "42",
				"dcil":          "4",
				"dcid":          "deadbeef",
			},
		)
	})

	It("marshals a header with a version number", func() {
		check(
			&wire.ExtendedHeader{
				PacketNumber: 42,
				Header:       wire.Header{Version: protocol.VersionNumber(0xdecafbad)},
			},
			map[string]interface{}{
				"packet_number": "42",
				"version":       "decafbad",
			},
		)
	})
})
