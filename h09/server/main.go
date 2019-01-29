package main

import (
	"context"
	"crypto/rand"
	"fmt"
	"io/ioutil"
	"strconv"
	"strings"

	quic "github.com/lucas-clemente/quic-go"
	"github.com/lucas-clemente/quic-go/internal/testdata"
	"github.com/lucas-clemente/quic-go/internal/utils"
)

func main() {
	utils.DefaultLogger.SetLogTimeFormat("15:05:03.000")
	if err := runServer(); err != nil {
		panic(err)
	}
}

func runServer() error {
	server, err := quic.ListenAddr(
		"0.0.0.0:4433",
		testdata.GetTLSConfig(),
		nil,
	)
	if err != nil {
		return err
	}

	for {
		conn, err := server.Accept(context.Background())
		if err != nil {
			return err
		}
		go func() {
			if err := handleConn(conn); err != nil {
				fmt.Println("Erorr handling conn: ", err)
			}
		}()
	}
}

func handleConn(conn quic.Session) error {
	for {
		str, err := conn.AcceptStream(context.Background())
		if err != nil {
			return err
		}
		go func() {
			if err := handleStream(str); err != nil {
				panic(err)
			}
		}()
	}
}

func handleStream(str quic.Stream) error {
	reqBytes, err := ioutil.ReadAll(str)
	if err != nil {
		return err
	}
	request := string(reqBytes)
	request = strings.TrimRight(request, "\r\n")
	request = strings.TrimRight(request, " ")
	fmt.Printf("Received request: %s\n", string(request))
	if request[:5] != "GET /" {
		str.CancelWrite(42)
		return nil
	}
	fmt.Println("numBytes: ", request[5:])
	numBytes, err := strconv.ParseInt(request[5:], 10, 64)
	if err != nil {
		fmt.Println(err)
		str.CancelWrite(43)
		return nil
	}
	if numBytes > 100*1<<10 {
		str.CancelWrite(43)
		return nil
	}
	defer str.Close()
	response := make([]byte, numBytes)
	rand.Read(response)
	_, err = str.Write(response)
	return err
}
