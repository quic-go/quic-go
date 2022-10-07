package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	quic "github.com/lucas-clemente/quic-go"
	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/logging"
	"github.com/lucas-clemente/quic-go/qlog"
	"io"
	"log"
	"os"
	"sync"
	"time"
)

const addr = "localhost:30000"

const message = "horisaki"

var wg sync.WaitGroup

type bufferedWriteCloser struct {
	*bufio.Writer
	io.Closer
}

// A ConnectionID in QUIC
type ConnectionID []byte

// NewBufferedWriteCloser creates an io.WriteCloser from a bufio.Writer and an io.Closer
func NewBufferedWriteCloser(writer *bufio.Writer, closer io.Closer) io.WriteCloser {
	return &bufferedWriteCloser{
		Writer: writer,
		Closer: closer,
	}
}

func (h bufferedWriteCloser) Close() error {
	if err := h.Writer.Flush(); err != nil {
		return err
	}
	return h.Closer.Close()
}

func quicConfig() *quic.Config {

	return &quic.Config{
		Versions:           []protocol.VersionNumber{protocol.Version1},
		ConnectionIDLength: 16,
		KeepAlivePeriod:    10 * time.Second,
		Tracer: qlog.NewTracer(func(_ logging.Perspective, connID []byte) io.WriteCloser {
			filename := fmt.Sprintf("qviz/client_%x.qlog", connID)
			f, err := os.Create(filename)
			if err != nil {
				log.Fatal(err)
			}
			log.Printf("Creating qlog file %s.\n", filename)
			return NewBufferedWriteCloser(bufio.NewWriter(f), f)
		}),
	}
}

func sendmessage(buf []byte, stream quic.Stream) {

	_, err := stream.Write(buf)
	if err != nil {
		panic(err)
	}

	buf_r := make([]byte, 20)
	recevemessage(buf_r, stream)
}

func recevemessage(buf_r []byte, stream quic.Stream) {

	_, err := stream.Read(buf_r)
	if err != nil {
		panic(err)
	}
	log.Println("Client Received:", string(buf_r))
}

func main() {
	tlsConf := &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"cyphonic"},
	}
	session, err := quic.DialAddr(addr, tlsConf, quicConfig())
	if err != nil {
		panic(err)
	}
	stream, err := session.OpenStreamSync(context.Background())
	if err != nil {
		panic(err)
	}
	log.Println("OpenStreamSync")

	buf := make([]byte, 4000)
	var str string
	var str1 = "UCLab"

	CID := quic.GetCID(session.RemoteAddr())
	fmt.Printf("ConnectionID:%s", CID)

	for {
		fmt.Scan(&str)
		buf = []byte(str1)

		sendmessage(buf, stream)
	}

	/*defer func() {
		stream.Close()
		log.Println("close the stream")
	}()*/

}

// ReadConnectionID reads a connection ID of length len from the given io.Reader.
// It returns io.EOF if there are not enough bytes to read.
func ReadConnectionID(r io.Reader, len int) (ConnectionID, error) {
	if len == 0 {
		return nil, nil
	}
	c := make(ConnectionID, len)
	_, err := io.ReadFull(r, c)
	if err == io.ErrUnexpectedEOF {
		return nil, io.EOF
	}
	return c, err
}
