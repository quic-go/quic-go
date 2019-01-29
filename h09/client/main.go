package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"io/ioutil"

	quic "github.com/lucas-clemente/quic-go"
	"github.com/lucas-clemente/quic-go/internal/utils"
)

func main() {
	utils.DefaultLogger.SetLogTimeFormat("15:05:03.000")
	flag.Parse()
	urls := flag.Args()

	if err := dial(urls[0]); err != nil {
		panic(err)
	}
}

func dial(url string) error {
	tlsConf := &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"http 0.9"},
	}
	conn, err := quic.DialAddr(url, tlsConf, nil)
	if err != nil {
		return err
	}
	str, err := conn.OpenStream()
	if err != nil {
		return err
	}
	if _, err := str.Write([]byte("GET /12345\r\n\r\n")); err != nil {
		return err
	}
	if err := str.Close(); err != nil {
		return err
	}
	response, err := ioutil.ReadAll(str)
	if err != nil {
		return err
	}
	fmt.Printf("Received response: %#x\n", response)
	if err := conn.Close(); err != nil {
		return err
	}
	return nil
}
