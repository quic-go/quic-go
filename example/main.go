package main

import (
	"bytes"
	"fmt"
	"net"
	"os"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"

	"github.com/lucas-clemente/quic-go"
	"github.com/lucas-clemente/quic-go/crypto"
	"github.com/lucas-clemente/quic-go/protocol"
	"github.com/lucas-clemente/quic-go/utils"
)

const (
	// QuicVersionNumber32 is the QUIC protocol version
	QuicVersionNumber32 = 32
)

func main() {
	QuicVersion32, _ := utils.ReadUint32BigEndian(bytes.NewReader([]byte{'Q', '0', 48 + (QuicVersionNumber32/10)%10, 48 + QuicVersionNumber32%10}))

	path := os.Getenv("GOPATH") + "/src/github.com/lucas-clemente/quic-go/example/"
	keyData, err := crypto.LoadKeyData(path+"cert.der", path+"key.der")
	if err != nil {
		panic(err)
	}

	serverConfig := quic.NewServerConfig(crypto.NewCurve25519KEX(), keyData)

	// TODO: When should a session be created?
	sessions := map[protocol.ConnectionID]*quic.Session{}

	addr, err := net.ResolveUDPAddr("udp", "localhost:6121")
	if err != nil {
		panic(err)
	}

	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		panic(err)
	}

	for {
		data := make([]byte, 0x10000)
		n, remoteAddr, err := conn.ReadFromUDP(data)
		if err != nil {
			panic(err)
		}
		data = data[:n]
		r := bytes.NewReader(data)

		fmt.Printf("Received %d bytes from %v\n", n, remoteAddr)

		publicHeader, err := quic.ParsePublicHeader(r)
		if err != nil {
			panic(err)
		}
		fmt.Printf("Got packet # %d\n", publicHeader.PacketNumber)

		// Send Version Negotiation Packet if the client is speaking a different protocol version
		if publicHeader.VersionFlag && publicHeader.QuicVersion != QuicVersion32 {
			fmt.Println("Sending VersionNegotiationPacket")
			fullReply := &bytes.Buffer{}
			responsePublicHeader := quic.PublicHeader{ConnectionID: publicHeader.ConnectionID, PacketNumber: 1, VersionFlag: true}
			err = responsePublicHeader.WritePublicHeader(fullReply)
			if err != nil {
				panic(err)
			}
			utils.WriteUint32BigEndian(fullReply, QuicVersion32)
			_, err = conn.WriteToUDP(fullReply.Bytes(), remoteAddr)
			if err != nil {
				panic(err)
			}
			continue
		}

		session, ok := sessions[publicHeader.ConnectionID]
		if !ok {
			session = quic.NewSession(conn, publicHeader.ConnectionID, serverConfig, handleStream)
			sessions[publicHeader.ConnectionID] = session
		}
		err = session.HandlePacket(remoteAddr, data[0:n-r.Len()], publicHeader, r)
		if err != nil {
			fmt.Printf("Error handling packet: %s\n", err.Error())
		}
	}
}

func handleStream(frame *quic.StreamFrame) *quic.StreamFrame {
	h2r := bytes.NewReader(frame.Data)
	var reply bytes.Buffer
	h2framer := http2.NewFramer(&reply, h2r)
	h2framer.ReadMetaHeaders = hpack.NewDecoder(1024, nil)
	h2frame, err := h2framer.ReadFrame()
	if err != nil {
		return nil
	}
	h2headersFrame := h2frame.(*http2.MetaHeadersFrame)
	fmt.Printf("%#v\n", h2headersFrame)

	var replyHeaders bytes.Buffer
	enc := hpack.NewEncoder(&replyHeaders)
	enc.WriteField(hpack.HeaderField{Name: ":status", Value: "204"})
	h2framer.WriteHeaders(http2.HeadersFrameParam{
		StreamID:      h2frame.Header().StreamID,
		EndHeaders:    true,
		BlockFragment: replyHeaders.Bytes(),
	})

	return &quic.StreamFrame{
		StreamID: frame.StreamID,
		Data:     reply.Bytes(),
	}
}
