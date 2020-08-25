package main

import (
	"bytes"
	"log"
	"math/rand"

	"github.com/lucas-clemente/quic-go/fuzzing/header"
	"github.com/lucas-clemente/quic-go/fuzzing/internal/helper"
	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/wire"
)

const version = protocol.VersionTLS

func getRandomData(l int) []byte {
	b := make([]byte, l)
	rand.Read(b)
	return b
}

func getVNP(src, dest protocol.ConnectionID, numVersions int) []byte {
	versions := make([]protocol.VersionNumber, numVersions)
	for i := 0; i < numVersions; i++ {
		versions[i] = protocol.VersionNumber(rand.Uint32())
	}
	data, err := wire.ComposeVersionNegotiation(src, dest, versions)
	if err != nil {
		log.Fatal(err)
	}
	return data
}

func main() {
	headers := []wire.Header{
		{ // Initial without token
			IsLongHeader:     true,
			SrcConnectionID:  protocol.ConnectionID(getRandomData(3)),
			DestConnectionID: protocol.ConnectionID(getRandomData(8)),
			Type:             protocol.PacketTypeInitial,
			Length:           protocol.ByteCount(rand.Intn(1000)),
			Version:          version,
		},
		{ // Initial without token, with zero-length src conn id
			IsLongHeader:     true,
			DestConnectionID: protocol.ConnectionID(getRandomData(8)),
			Type:             protocol.PacketTypeInitial,
			Length:           protocol.ByteCount(rand.Intn(1000)),
			Version:          version,
		},
		{ // Initial with Token
			IsLongHeader:     true,
			SrcConnectionID:  protocol.ConnectionID(getRandomData(10)),
			DestConnectionID: protocol.ConnectionID(getRandomData(19)),
			Type:             protocol.PacketTypeInitial,
			Length:           protocol.ByteCount(rand.Intn(1000)),
			Version:          version,
			Token:            getRandomData(25),
		},
		{ // Handshake packet
			IsLongHeader:     true,
			SrcConnectionID:  protocol.ConnectionID(getRandomData(5)),
			DestConnectionID: protocol.ConnectionID(getRandomData(10)),
			Type:             protocol.PacketTypeHandshake,
			Length:           protocol.ByteCount(rand.Intn(1000)),
			Version:          version,
		},
		{ // Handshake packet, with zero-length src conn id
			IsLongHeader:     true,
			DestConnectionID: protocol.ConnectionID(getRandomData(12)),
			Type:             protocol.PacketTypeHandshake,
			Length:           protocol.ByteCount(rand.Intn(1000)),
			Version:          version,
		},
		{ // 0-RTT packet
			IsLongHeader:     true,
			SrcConnectionID:  protocol.ConnectionID(getRandomData(8)),
			DestConnectionID: protocol.ConnectionID(getRandomData(9)),
			Type:             protocol.PacketType0RTT,
			Length:           protocol.ByteCount(rand.Intn(1000)),
			Version:          version,
		},
		{ // Retry Packet, with empty orig dest conn id
			IsLongHeader:     true,
			SrcConnectionID:  protocol.ConnectionID(getRandomData(8)),
			DestConnectionID: protocol.ConnectionID(getRandomData(9)),
			Type:             protocol.PacketTypeRetry,
			Token:            getRandomData(1000),
			Version:          version,
		},
		{ // Short-Header
			DestConnectionID: protocol.ConnectionID(getRandomData(8)),
		},
	}

	for _, h := range headers {
		extHdr := &wire.ExtendedHeader{
			Header:          h,
			PacketNumberLen: protocol.PacketNumberLen(rand.Intn(4) + 1),
			PacketNumber:    protocol.PacketNumber(rand.Uint64()),
		}
		b := &bytes.Buffer{}
		if err := extHdr.Write(b, version); err != nil {
			log.Fatal(err)
		}
		if h.Type == protocol.PacketTypeRetry {
			b.Write([]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16})
		}
		if h.Length > 0 {
			b.Write(make([]byte, h.Length))
		}

		if err := helper.WriteCorpusFileWithPrefix("corpus", b.Bytes(), header.PrefixLen); err != nil {
			log.Fatal(err)
		}
	}

	vnps := [][]byte{
		getVNP(
			protocol.ConnectionID(getRandomData(8)),
			protocol.ConnectionID(getRandomData(10)),
			4,
		),
		getVNP(
			protocol.ConnectionID(getRandomData(10)),
			protocol.ConnectionID(getRandomData(5)),
			0,
		),
		getVNP(
			protocol.ConnectionID(getRandomData(3)),
			protocol.ConnectionID(getRandomData(19)),
			100,
		),
		getVNP(
			protocol.ConnectionID(getRandomData(3)),
			nil,
			20,
		),
		getVNP(
			nil,
			protocol.ConnectionID(getRandomData(10)),
			5,
		),
	}

	for _, vnp := range vnps {
		if err := helper.WriteCorpusFileWithPrefix("corpus", vnp, header.PrefixLen); err != nil {
			log.Fatal(err)
		}
	}
}
