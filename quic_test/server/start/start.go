package start

import (
	"context"
	"github.com/lucas-clemente/quic-go"
	"log"
	"net"
	"sync"
)

var wg sync.WaitGroup
var flag = 0
var m = map[net.Addr]quic.Stream{}

func sendmessage(buf_r []byte, stream quic.Stream) {

	_, err := stream.Write([]byte("not finish"))
	if err != nil {
		panic(err)
	}
}

func finishmessage(buf_r []byte, stream quic.Stream) {

	defer wg.Done()

	_, err := stream.Write([]byte("finish"))
	if err != nil {
		panic(err)
	} else {
		flag = 1
	}
}

func recevemessage(buf_r []byte, stream quic.Stream) {

	if string(buf_r[0:4]) == "exit" {
		finishmessage(buf_r, stream)
	} else {
		sendmessage(buf_r, stream)
	}
}

func Start(conn quic.Connection) {

	stream, err := conn.AcceptStream(context.Background())
	if err != nil {
		panic(err)
	}
	log.Println("AcceptStream")

	buf_r := make([]byte, 4000)

	wg.Add(1)
	flag = 0

	for {
		recevemessage(buf_r, stream)

		if flag == 1 {
			break
		}
	}

	wg.Wait()

}
