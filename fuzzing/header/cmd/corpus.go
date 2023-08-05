package main

import (
	"log"

	"golang.org/x/exp/rand"

	"github.com/quic-go/quic-go/fuzzing/header"
	"github.com/quic-go/quic-go/fuzzing/internal/helper"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/wire"
)

const version = protocol.Version1

func getRandomData(l int) []byte {
	b := make([]byte, l)
	rand.Read(b)
	return b
}

func getVNP(src, dest protocol.ArbitraryLenConnectionID, numVersions int) []byte {
	versions := make([]protocol.VersionNumber, numVersions)
	for i := 0; i < numVersions; i++ {
		versions[i] = protocol.VersionNumber(rand.Uint32())
	}
	return wire.ComposeVersionNegotiation(src, dest, versions)
}

func main() {
	headers := []wire.Header{
		{ // Initial without token
			SrcConnectionID:  protocol.ParseConnectionID(getRandomData(3)),
			DestConnectionID: protocol.ParseConnectionID(getRandomData(8)),
			Type:             protocol.PacketTypeInitial,
			Length:           protocol.ByteCount(rand.Intn(1000)),
			Version:          version,
		},
		{ // Initial without token, with zero-length src conn id
			DestConnectionID: protocol.ParseConnectionID(getRandomData(8)),
			Type:             protocol.PacketTypeInitial,
			Length:           protocol.ByteCount(rand.Intn(1000)),
			Version:          version,
		},
		{ // Initial with Token
			SrcConnectionID:  protocol.ParseConnectionID(getRandomData(10)),
			DestConnectionID: protocol.ParseConnectionID(getRandomData(19)),
			Type:             protocol.PacketTypeInitial,
			Length:           protocol.ByteCount(rand.Intn(1000)),
			Version:          version,
			Token:            getRandomData(25),
		},
		{ // Handshake packet
			SrcConnectionID:  protocol.ParseConnectionID(getRandomData(5)),
			DestConnectionID: protocol.ParseConnectionID(getRandomData(10)),
			Type:             protocol.PacketTypeHandshake,
			Length:           protocol.ByteCount(rand.Intn(1000)),
			Version:          version,
		},
		{ // Handshake packet, with zero-length src conn id
			DestConnectionID: protocol.ParseConnectionID(getRandomData(12)),
			Type:             protocol.PacketTypeHandshake,
			Length:           protocol.ByteCount(rand.Intn(1000)),
			Version:          version,
		},
		{ // 0-RTT packet
			SrcConnectionID:  protocol.ParseConnectionID(getRandomData(8)),
			DestConnectionID: protocol.ParseConnectionID(getRandomData(9)),
			Type:             protocol.PacketType0RTT,
			Length:           protocol.ByteCount(rand.Intn(1000)),
			Version:          version,
		},
		{ // Retry Packet, with empty orig dest conn id
			SrcConnectionID:  protocol.ParseConnectionID(getRandomData(8)),
			DestConnectionID: protocol.ParseConnectionID(getRandomData(9)),
			Type:             protocol.PacketTypeRetry,
			Token:            getRandomData(1000),
			Version:          version,
		},
	}

	for _, h := range headers {
		extHdr := &wire.ExtendedHeader{
			Header:          h,
			PacketNumberLen: protocol.PacketNumberLen(rand.Intn(4) + 1),
			PacketNumber:    protocol.PacketNumber(rand.Uint64()),
		}
		b, err := extHdr.Append(nil, version)
		if err != nil {
			log.Fatal(err)
		}
		if h.Type == protocol.PacketTypeRetry {
			b = append(b, []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}...)
		}
		if h.Length > 0 {
			b = append(b, make([]byte, h.Length)...)
		}

		if err := helper.WriteCorpusFileWithPrefix("corpus", b, header.PrefixLen); err != nil {
			log.Fatal(err)
		}
	}

	// short header
	b, err := wire.AppendShortHeader(nil, protocol.ParseConnectionID(getRandomData(8)), 1337, protocol.PacketNumberLen2, protocol.KeyPhaseOne)
	if err != nil {
		log.Fatal(err)
	}
	if err := helper.WriteCorpusFileWithPrefix("corpus", b, header.PrefixLen); err != nil {
		log.Fatal(err)
	}

	vnps := [][]byte{
		getVNP(
			protocol.ArbitraryLenConnectionID(getRandomData(8)),
			protocol.ArbitraryLenConnectionID(getRandomData(10)),
			4,
		),
		getVNP(
			protocol.ArbitraryLenConnectionID(getRandomData(10)),
			protocol.ArbitraryLenConnectionID(getRandomData(5)),
			0,
		),
		getVNP(
			protocol.ArbitraryLenConnectionID(getRandomData(3)),
			protocol.ArbitraryLenConnectionID(getRandomData(19)),
			100,
		),
		getVNP(
			protocol.ArbitraryLenConnectionID(getRandomData(3)),
			nil,
			20,
		),
		getVNP(
			nil,
			protocol.ArbitraryLenConnectionID(getRandomData(10)),
			5,
		),
	}

	for _, vnp := range vnps {
		if err := helper.WriteCorpusFileWithPrefix("corpus", vnp, header.PrefixLen); err != nil {
			log.Fatal(err)
		}
	}
}
