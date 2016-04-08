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
}
