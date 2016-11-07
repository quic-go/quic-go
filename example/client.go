package main

import (
	"bytes"
	"fmt"
	"math/rand"
	"net"
	"time"

	quic "github.com/lucas-clemente/quic-go"
	"github.com/lucas-clemente/quic-go/crypto"
	"github.com/lucas-clemente/quic-go/protocol"
)

func main() {
	addr := "quic.clemente.io:6121"

	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		panic(err)
	}

	fmt.Println(udpAddr.String())

	conn, err := net.DialUDP("udp", nil, udpAddr)
	defer conn.Close()
	if err != nil {
		panic(err)
	}

	rand.Seed(time.Now().UTC().UnixNano())
	connectionID := protocol.ConnectionID(0x1337 + rand.Int63())
	packetNumber := protocol.PacketNumber(1)

	ph := quic.PublicHeader{
		ConnectionID:    connectionID,
		PacketNumber:    packetNumber,
		PacketNumberLen: protocol.PacketNumberLen2,
		VersionFlag:     true,
		VersionNumber:   protocol.Version34,
	}

	raw := make([]byte, 0, protocol.MaxPacketSize)
	buffer := bytes.NewBuffer(raw)

	err = ph.Write(buffer, protocol.Version34, protocol.PerspectiveClient)
	if err != nil {
		panic(err)
	}
	payloadStartIndex := buffer.Len()

	raw = raw[0:buffer.Len()]
	aead := crypto.NullAEAD{}
	aead.Seal(raw[payloadStartIndex:payloadStartIndex], raw[payloadStartIndex:], packetNumber, raw[:payloadStartIndex])
	raw = raw[0 : buffer.Len()+12]

	conn.Write(raw)

	for {
		data := make([]byte, 1500)
		n, _, err := conn.ReadFromUDP(data)
		if err != nil {
			panic(err)
		}
		data = data[:n]
		fmt.Printf("Response length: %d\n", n)
		fmt.Println(data)
	}
}
