package main

import (
	"bytes"
	"fmt"
	"net/http"
	"os"
	"strconv"

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

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("Hello world!"))
	})

	err = server.ListenAndServe("localhost:6121")
	if err != nil {
		panic(err)
	}
}

type responseWriter struct {
	header       http.Header
	headerStream *quic.Stream
	session      *quic.Session
	status       int
	dataStreamID protocol.StreamID
}

func (w *responseWriter) Header() http.Header {
	return w.header
}

func (w *responseWriter) WriteHeader(status int) {
	w.status = status
}

func (w *responseWriter) Write(p []byte) (int, error) {
	if w.status == 0 {
		w.WriteHeader(200)
	}

	var headers bytes.Buffer
	enc := hpack.NewEncoder(&headers)
	enc.WriteField(hpack.HeaderField{Name: ":status", Value: strconv.Itoa(w.status)})
	// enc.WriteField(hpack.HeaderField{Name: "content-length", Value: strconv.Itoa(len(p))})
	// enc.WriteField(hpack.HeaderField{Name: "content-type", Value: http.DetectContentType(p)})

	for k, v := range w.header {
		enc.WriteField(hpack.HeaderField{Name: k, Value: v[0]})
	}

	h2framer := http2.NewFramer(w.headerStream, nil)
	h2framer.WriteHeaders(http2.HeadersFrameParam{
		StreamID:      uint32(w.dataStreamID),
		EndHeaders:    true,
		BlockFragment: headers.Bytes(),
	})

	if len(p) != 0 {
		dataStream, err := w.session.NewStream(w.dataStreamID)
		if err != nil {
			return 0, fmt.Errorf("error creating data stream: %s\n", err.Error())
		}
		defer dataStream.Close()
		return dataStream.Write(p)
	}

	return 0, nil
}

func handleStream(session *quic.Session, headerStream *quic.Stream) {
	hpackDecoder := hpack.NewDecoder(1024, nil)
	h2framer := http2.NewFramer(nil, headerStream)
	h2framer.ReadMetaHeaders = hpackDecoder

	go func() {
		for {
			h2frame, err := h2framer.ReadFrame()
			if err != nil {
				fmt.Printf("invalid http2 frame: %s\n", err.Error())
				continue
			}
			h2headersFrame := h2frame.(*http2.MetaHeadersFrame)
			fmt.Printf("Request: %s %s://%s%s\n", h2headersFrame.PseudoValue("method"), h2headersFrame.PseudoValue("scheme"), h2headersFrame.PseudoValue("authority"), h2headersFrame.PseudoValue("path"))

			req, err := http.NewRequest(h2headersFrame.PseudoValue("method"), h2headersFrame.PseudoValue("path"), nil)
			if err != nil {
				fmt.Printf("invalid http2 frame: %s\n", err.Error())
				continue
			}

			responseWriter := &responseWriter{
				header:       http.Header{},
				headerStream: headerStream,
				dataStreamID: protocol.StreamID(h2headersFrame.StreamID),
				session:      session,
			}

			go http.DefaultServeMux.ServeHTTP(responseWriter, req)
		}
	}()
}
