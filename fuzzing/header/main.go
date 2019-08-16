// +build !gofuzz

package main

import (
	"bytes"
	"fmt"
	"math/rand"
	"os"

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
		panic(err)
	}
	return data
}

func main() {
	rand.Seed(1337)

	headers := []wire.Header{
		wire.Header{ // Initial without token
			IsLongHeader:     true,
			SrcConnectionID:  protocol.ConnectionID(getRandomData(3)),
			DestConnectionID: protocol.ConnectionID(getRandomData(8)),
			Type:             protocol.PacketTypeInitial,
			Length:           protocol.ByteCount(rand.Intn(1000)),
			Version:          version,
		},
		wire.Header{ // Initial without token, with zero-length src conn id
			IsLongHeader:     true,
			DestConnectionID: protocol.ConnectionID(getRandomData(8)),
			Type:             protocol.PacketTypeInitial,
			Length:           protocol.ByteCount(rand.Intn(1000)),
			Version:          version,
		},
		wire.Header{ // Initial with Token
			IsLongHeader:     true,
			SrcConnectionID:  protocol.ConnectionID(getRandomData(10)),
			DestConnectionID: protocol.ConnectionID(getRandomData(19)),
			Type:             protocol.PacketTypeInitial,
			Length:           protocol.ByteCount(rand.Intn(1000)),
			Version:          version,
			Token:            getRandomData(25),
		},
		wire.Header{ // Handshake packet
			IsLongHeader:     true,
			SrcConnectionID:  protocol.ConnectionID(getRandomData(5)),
			DestConnectionID: protocol.ConnectionID(getRandomData(10)),
			Type:             protocol.PacketTypeHandshake,
			Length:           protocol.ByteCount(rand.Intn(1000)),
			Version:          version,
		},
		wire.Header{ // Handshake packet, with zero-length src conn id
			IsLongHeader:     true,
			DestConnectionID: protocol.ConnectionID(getRandomData(12)),
			Type:             protocol.PacketTypeHandshake,
			Length:           protocol.ByteCount(rand.Intn(1000)),
			Version:          version,
		},
		wire.Header{ // 0-RTT packet
			IsLongHeader:     true,
			SrcConnectionID:  protocol.ConnectionID(getRandomData(8)),
			DestConnectionID: protocol.ConnectionID(getRandomData(9)),
			Type:             protocol.PacketType0RTT,
			Length:           protocol.ByteCount(rand.Intn(1000)),
			Version:          version,
		},
		wire.Header{ // Retry Packet
			IsLongHeader:         true,
			SrcConnectionID:      protocol.ConnectionID(getRandomData(8)),
			DestConnectionID:     protocol.ConnectionID(getRandomData(9)),
			OrigDestConnectionID: protocol.ConnectionID(getRandomData(10)),
			Type:                 protocol.PacketTypeRetry,
			Token:                getRandomData(10),
			Version:              version,
		},
		wire.Header{ // Retry Packet, with empty orig dest conn id
			IsLongHeader:     true,
			SrcConnectionID:  protocol.ConnectionID(getRandomData(8)),
			DestConnectionID: protocol.ConnectionID(getRandomData(9)),
			Type:             protocol.PacketTypeRetry,
			Token:            getRandomData(1000),
			Version:          version,
		},
		wire.Header{ // Retry Packet, with zero-length dest conn id
			IsLongHeader:         true,
			SrcConnectionID:      protocol.ConnectionID(getRandomData(8)),
			OrigDestConnectionID: protocol.ConnectionID(getRandomData(10)),
			Type:                 protocol.PacketTypeRetry,
			Token:                getRandomData(1000),
			Version:              version,
		},
		wire.Header{ // Short-Header
			DestConnectionID: protocol.ConnectionID(getRandomData(8)),
		},
	}

	for i, h := range headers {
		extHdr := &wire.ExtendedHeader{
			Header:          h,
			PacketNumberLen: protocol.PacketNumberLen(rand.Intn(4) + 1),
			PacketNumber:    protocol.PacketNumber(rand.Uint64()),
		}
		b := &bytes.Buffer{}
		if err := extHdr.Write(b, version); err != nil {
			panic(err)
		}
		if h.Length > 0 {
			b.Write(make([]byte, h.Length))
		}

		if err := writeCorpusFile(fmt.Sprintf("header-%d", i), b.Bytes()); err != nil {
			panic(err)
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

	for i, vnp := range vnps {
		if err := writeCorpusFile(fmt.Sprintf("vnp-%d", i), vnp); err != nil {
			panic(err)
		}
	}

}

func writeCorpusFile(name string, data []byte) error {
	file, err := os.Create("corpus/" + name)
	if err != nil {
		return err
	}
	data = append(getRandomData(1), data...)
	if _, err := file.Write(data); err != nil {
		return err
	}
	return file.Close()
}
