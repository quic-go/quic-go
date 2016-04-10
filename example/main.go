package main

import (
	"bytes"
	"errors"
	"fmt"
	"net"

	"github.com/lucas-clemente/quic-go"
	"github.com/lucas-clemente/quic-go/crypto"
)

func main() {
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

	if publicHeader.VersionFlag && publicHeader.QuicVersion != 0x51303330 {
		panic("only version Q030 supported")
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
	fmt.Printf("Talking to: %s\n", string(cryptoData[quic.TagUAID]))

	serverConfig := &bytes.Buffer{}
	quic.WriteCryptoMessage(serverConfig, quic.TagSCFG, map[quic.Tag][]byte{
		quic.TagSCID: []byte{0xC5, 0x1C, 0x73, 0x6B, 0x8F, 0x48, 0x49, 0xAE, 0xB3, 0x00, 0xA2, 0xD4, 0x4B, 0xA0, 0xCF, 0xDF},
		quic.TagKEXS: []byte("C255"),
		quic.TagAEAD: []byte("AESG"),
		quic.TagPUBS: []byte{},
		quic.TagORBT: []byte{0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7},
		quic.TagEXPY: []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		quic.TagVER:  []byte("Q030"),
	})

	serverReply := &bytes.Buffer{}
	quic.WriteCryptoMessage(serverReply, quic.TagREJ, map[quic.Tag][]byte{
		quic.TagSCFG: serverConfig.Bytes(),
	})
}
