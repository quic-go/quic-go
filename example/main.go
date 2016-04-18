package main

import (
	"bytes"
	"fmt"
	"os"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"

	"github.com/lucas-clemente/quic-go"
	"github.com/lucas-clemente/quic-go/protocol"
)

var supportedVersions = map[protocol.VersionNumber]bool{
	30: true,
	32: true,
}

func main() {
	path := os.Getenv("GOPATH") + "/src/github.com/lucas-clemente/quic-go/example/"

	server, err := quic.NewServer(path+"cert.der", path+"key.der", handleStream)
	if err != nil {
		panic(err)
	}

	err = server.ListenAndServe("localhost:6121")
	if err != nil {
		panic(err)
	}
}

func handleStream(session *quic.Session, stream *quic.Stream) {
	h2framer := http2.NewFramer(stream, stream)
	h2framer.ReadMetaHeaders = hpack.NewDecoder(1024, nil)
	h2frame, err := h2framer.ReadFrame()
	if err != nil {
		fmt.Printf("invalid http2 frame: %s", err.Error())
		return
	}
	h2headersFrame := h2frame.(*http2.MetaHeadersFrame)
	fmt.Printf("Request: %s %s://%s%s\n", h2headersFrame.PseudoValue("method"), h2headersFrame.PseudoValue("scheme"), h2headersFrame.PseudoValue("authority"), h2headersFrame.PseudoValue("path"))

	var replyHeaders bytes.Buffer
	enc := hpack.NewEncoder(&replyHeaders)
	enc.WriteField(hpack.HeaderField{Name: ":status", Value: "200"})
	enc.WriteField(hpack.HeaderField{Name: "content-type", Value: "text/plain"})
	enc.WriteField(hpack.HeaderField{Name: "content-length", Value: "12"})
	h2framer.WriteHeaders(http2.HeadersFrameParam{
		StreamID:      h2frame.Header().StreamID,
		EndHeaders:    true,
		BlockFragment: replyHeaders.Bytes(),
	})

	dataStream, err := session.NewStream(protocol.StreamID(h2frame.Header().StreamID))
	if err != nil {
		fmt.Printf("error creating stream: %s", err.Error())
		return
	}

	dataStream.Write([]byte("Hello World!"))
	dataStream.Close()
}
