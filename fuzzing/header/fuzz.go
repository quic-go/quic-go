package header

import (
	"bytes"
	"fmt"

	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/wire"
)

const version = protocol.VersionTLS

// PrefixLen is the number of bytes used for configuration
const PrefixLen = 1

// Fuzz fuzzes the QUIC header.
//
//go:generate go run ./cmd/corpus.go
func Fuzz(data []byte) int {
	if len(data) < PrefixLen {
		return 0
	}
	connIDLen := int(data[0] % 21)
	data = data[PrefixLen:]

	if wire.IsVersionNegotiationPacket(data) {
		return fuzzVNP(data)
	}
	connID, err := wire.ParseConnectionID(data, connIDLen)
	if err != nil {
		return 0
	}

	if !wire.IsLongHeaderPacket(data[0]) {
		wire.ParseShortHeader(data, connIDLen)
		return 1
	}

	is0RTTPacket := wire.Is0RTTPacket(data)
	hdr, _, _, err := wire.ParsePacket(data)
	if err != nil {
		return 0
	}
	if hdr.DestConnectionID != connID {
		panic(fmt.Sprintf("Expected connection IDs to match: %s vs %s", hdr.DestConnectionID, connID))
	}
	if (hdr.Type == protocol.PacketType0RTT) != is0RTTPacket {
		panic("inconsistent 0-RTT packet detection")
	}

	var extHdr *wire.ExtendedHeader
	// Parse the extended header, if this is not a Retry packet.
	if hdr.Type == protocol.PacketTypeRetry {
		extHdr = &wire.ExtendedHeader{Header: *hdr}
	} else {
		var err error
		extHdr, err = hdr.ParseExtended(bytes.NewReader(data), version)
		if err != nil {
			return 0
		}
	}
	// We always use a 2-byte encoding for the Length field in Long Header packets.
	// Serializing the header will fail when using a higher value.
	if hdr.Length > 16383 {
		return 1
	}
	b, err := extHdr.Append(nil, version)
	if err != nil {
		// We are able to parse packets with connection IDs longer than 20 bytes,
		// but in QUIC version 1, we don't write headers with longer connection IDs.
		if hdr.DestConnectionID.Len() <= protocol.MaxConnIDLen &&
			hdr.SrcConnectionID.Len() <= protocol.MaxConnIDLen {
			panic(err)
		}
		return 0
	}
	// GetLength is not implemented for Retry packets
	if hdr.Type != protocol.PacketTypeRetry {
		if expLen := extHdr.GetLength(version); expLen != protocol.ByteCount(len(b)) {
			panic(fmt.Sprintf("inconsistent header length: %#v. Expected %d, got %d", extHdr, expLen, len(b)))
		}
	}
	return 1
}

func fuzzVNP(data []byte) int {
	connID, err := wire.ParseConnectionID(data, 0)
	if err != nil {
		return 0
	}
	dest, src, versions, err := wire.ParseVersionNegotiationPacket(data)
	if err != nil {
		return 0
	}
	if !bytes.Equal(dest, connID.Bytes()) {
		panic("connection IDs don't match")
	}
	if len(versions) == 0 {
		panic("no versions")
	}
	wire.ComposeVersionNegotiation(src, dest, versions)
	return 1
}
