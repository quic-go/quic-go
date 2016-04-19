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
	session      *quic.Session
	dataStreamID protocol.StreamID
	headerStream *quic.Stream
	dataStream   *quic.Stream

	header        http.Header
	headerWritten bool
}

func (w *responseWriter) Header() http.Header {
	return w.header
}

func (w *responseWriter) WriteHeader(status int) {
	w.headerWritten = true

	var headers bytes.Buffer
	enc := hpack.NewEncoder(&headers)
	enc.WriteField(hpack.HeaderField{Name: ":status", Value: strconv.Itoa(status)})
	// enc.WriteField(hpack.HeaderField{Name: "content-length", Value: strconv.Itoa(len(p))})
	// enc.WriteField(hpack.HeaderField{Name: "content-type", Value: http.DetectContentType(p)})

	for k, v := range w.header {
		enc.WriteField(hpack.HeaderField{Name: k, Value: v[0]})
	}

	fmt.Printf("responding with %d %#v\n", status, w.header)
	h2framer := http2.NewFramer(w.headerStream, nil)
	h2framer.WriteHeaders(http2.HeadersFrameParam{
		StreamID:      uint32(w.dataStreamID),
		EndHeaders:    true,
		BlockFragment: headers.Bytes(),
	})
}

func (w *responseWriter) Write(p []byte) (int, error) {
	if !w.headerWritten {
		w.WriteHeader(200)
	}

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
	hpackDecoder := hpack.NewDecoder(4096, nil)
	h2framer := http2.NewFramer(nil, headerStream)

	go func() {
		for {
			h2frame, err := h2framer.ReadFrame()
			if err != nil {
				fmt.Printf("invalid http2 frame: %s\n", err.Error())
				continue
			}
			h2headersFrame := h2frame.(*http2.HeadersFrame)
			if !h2headersFrame.HeadersEnded() {
				fmt.Printf("http2 header continuation not implemented")
				continue
			}
			headers, err := hpackDecoder.DecodeFull(h2headersFrame.HeaderBlockFragment())
			if err != nil {
				fmt.Printf("invalid http2 headers encoding: %s\n", err.Error())
				continue
			}

			headersMap := map[string]string{}
			for _, h := range headers {
				headersMap[h.Name] = h.Value
			}

			fmt.Printf("Request: %s %s://%s%s on stream %d\n", headersMap[":method"], headersMap[":scheme"], headersMap[":authority"], headersMap[":path"], h2headersFrame.StreamID)

			req, err := http.NewRequest(headersMap[":method"], headersMap[":path"], nil)
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
