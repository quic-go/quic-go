package main

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"os"

	"github.com/lucas-clemente/quic-go"
	"github.com/lucas-clemente/quic-go/crypto"
)

const (
	// QuicVersion32 is Q032
	QuicVersion32 uint32 = 'Q' + '0'<<8 + '3'<<16 + '2'<<24
)

func main() {
	path := os.Getenv("GOPATH") + "/src/github.com/lucas-clemente/quic-go/example/"
	keyData, err := crypto.LoadKeyData(path+"cert.der", path+"key.der")
	if err != nil {
		panic(err)
	}

	addr, err := net.ResolveUDPAddr("udp", "localhost:6121")
	if err != nil {
		panic(err)
	}

	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		panic(err)
	}

	data := make([]byte, 0x10000)
	n, remoteAddr, err := conn.ReadFromUDP(data)
	if err != nil {
		panic(err)
	}
	data = data[:n]
	r := bytes.NewReader(data)

	fmt.Printf("Number of bytes: %d\n", n)
	fmt.Printf("Remote addr: %v\n", remoteAddr)

	publicHeader, err := quic.ParsePublicHeader(r)
	if err != nil {
		panic(err)
	}

	if publicHeader.VersionFlag && publicHeader.QuicVersion < QuicVersion32 {
		println(publicHeader.QuicVersion)
		panic("only versions >= Q032 supported")
	}

	nullAEAD := &crypto.NullAEAD{}
	r, err = nullAEAD.Open(data[0:int(r.Size())-r.Len()], r)
	if err != nil {
		panic(err)
	}

	privateFlag, err := r.ReadByte()
	if err != nil {
		panic(err)
	}

	if privateFlag&0x02 > 0 || privateFlag&0x04 > 0 {
		panic(errors.New("FEC packets are not implemented"))
	}

	frame, err := quic.ParseStreamFrame(r)
	if err != nil {
		panic(err)
	}

	messageTag, cryptoData, err := quic.ParseCryptoMessage(frame.Data)
	if err != nil {
		panic(err)
	}

	fmt.Printf("Tag: %d\n", messageTag)
	fmt.Printf("Talking to: %q\n", cryptoData[quic.TagUAID])

	kex := crypto.NewCurve25519KEX()

	serverConfig := &bytes.Buffer{}
	quic.WriteCryptoMessage(serverConfig, quic.TagSCFG, map[quic.Tag][]byte{
		quic.TagSCID: []byte{0xC5, 0x1C, 0x73, 0x6B, 0x8F, 0x48, 0x49, 0xAE, 0xB3, 0x00, 0xA2, 0xD4, 0x4B, 0xA0, 0xCF, 0xDF},
		quic.TagKEXS: []byte("C255"),
		quic.TagAEAD: []byte("AESG"),
		quic.TagPUBS: append([]byte{0x20, 0x00, 0x00}, kex.PublicKey()...),
		quic.TagOBIT: []byte{0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7},
		quic.TagEXPY: []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		quic.TagVER:  []byte("Q032"),
	})

	proof, err := keyData.SignServerProof(frame.Data, serverConfig.Bytes())
	if err != nil {
		panic(err)
	}
	serverReply := &bytes.Buffer{}
	quic.WriteCryptoMessage(serverReply, quic.TagREJ, map[quic.Tag][]byte{
		quic.TagSCFG: serverConfig.Bytes(),
		quic.TagCERT: keyData.GetCERTdata(),
		quic.TagPROF: proof,
	})

	replyFrame := &bytes.Buffer{}
	replyFrame.WriteByte(0) // Private header
	quic.WriteAckFrame(replyFrame, &quic.AckFrame{
		LargestObserved: 1,
	})
	quic.WriteStreamFrame(replyFrame, &quic.StreamFrame{
		StreamID: 1,
		Data:     serverReply.Bytes(),
	})

	fullReply := &bytes.Buffer{}
	quic.WritePublicHeader(fullReply, &quic.PublicHeader{
		ConnectionID: publicHeader.ConnectionID,
		PacketNumber: 1,
	})

	nullAEAD.Seal(fullReply, fullReply.Bytes(), replyFrame.Bytes())

	conn.WriteToUDP(fullReply.Bytes(), remoteAddr)

	n, _, err = conn.ReadFromUDP(data)
	if err != nil {
		panic(err)
	}
	data = data[:n]
	r = bytes.NewReader(data)

	fmt.Printf("%v\n", data)

	publicHeader, err = quic.ParsePublicHeader(r)
	if err != nil {
		panic(err)
	}
	fmt.Printf("%#v\n", publicHeader)
}
