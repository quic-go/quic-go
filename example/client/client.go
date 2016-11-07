package main

import (
	"bytes"
	"fmt"
	"math/rand"
	"net"
	"time"

	quic "github.com/lucas-clemente/quic-go"
	"github.com/lucas-clemente/quic-go/crypto"
	"github.com/lucas-clemente/quic-go/frames"
	"github.com/lucas-clemente/quic-go/handshake"
	"github.com/lucas-clemente/quic-go/protocol"
)

func main() {
	addr := "quic.clemente.io:6121"

	conn, err := connect(addr)
	defer conn.Close()
	if err != nil {
		panic(err)
	}

	rand.Seed(time.Now().UTC().UnixNano())
	connectionID := protocol.ConnectionID(0x1337 + rand.Int63())
	packetNumber := protocol.PacketNumber(1)
	version := protocol.Version34

	ph := quic.PublicHeader{
		ConnectionID:    connectionID,
		PacketNumber:    packetNumber,
		PacketNumberLen: protocol.PacketNumberLen6,
		VersionFlag:     true,
		VersionNumber:   version,
	}

	raw := make([]byte, 0, protocol.MaxPacketSize)
	buffer := bytes.NewBuffer(raw)

	err = ph.Write(buffer, protocol.Version34, protocol.PerspectiveClient)
	if err != nil {
		panic(err)
	}
	payloadStartIndex := buffer.Len()

	b := &bytes.Buffer{}

	tags := make(map[handshake.Tag][]byte)
	tags[handshake.TagSNI] = []byte("quic.clemente.io")
	tags[handshake.TagPDMD] = []byte("X509")
	tags[handshake.TagPAD] = bytes.Repeat([]byte("F"), 1000)
	handshake.WriteHandshakeMessage(b, handshake.TagCHLO, tags)

	frame := frames.StreamFrame{
		StreamID:       1,
		DataLenPresent: true,
		Data:           b.Bytes(),
	}

	frame.Write(buffer, version)

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

func connect(addr string) (*net.UDPConn, error) {
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}

	conn, err := net.DialUDP("udp", nil, udpAddr)
	if err != nil {
		return nil, err
	}

	return conn, nil
}
