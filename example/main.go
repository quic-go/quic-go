package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strconv"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"

	"github.com/lucas-clemente/quic-go"
	"github.com/lucas-clemente/quic-go/protocol"
	"github.com/lucas-clemente/quic-go/utils"
)

func main() {
	bindTo := flag.String("bind", "localhost", "bind to")
	certPathDefault := os.Getenv("GOPATH") + "/src/github.com/lucas-clemente/quic-go/example/"
	certPath := flag.String("certpath", certPathDefault, "certificate directory")
	www := flag.String("www", "/var/www", "www data")
	flag.Parse()

	server, err := quic.NewServer(*certPath+"cert.der", *certPath+"key.der", handleStream)
	if err != nil {
		panic(err)
	}

	http.Handle("/", http.FileServer(http.Dir(*www)))

	err = server.ListenAndServe(*bindTo + ":6121")
	if err != nil {
		panic(err)
	}
}

type responseWriter struct {
	session      *quic.Session
	dataStreamID protocol.StreamID
	headerStream utils.Stream
	dataStream   utils.Stream

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

	for k, v := range w.header {
		enc.WriteField(hpack.HeaderField{Name: k, Value: v[0]})
	}

	fmt.Printf("Responding with %d %#v\n", status, w.header)
	h2framer := http2.NewFramer(w.headerStream, nil)
	h2framer.WriteHeaders(http2.HeadersFrameParam{
		StreamID:      uint32(w.dataStreamID),
		EndHeaders:    true,
		BlockFragment: headers.Bytes(),
	})
}

func (w *responseWriter) Write(p []byte) (int, error) {
	fmt.Printf("%#v\n", w.header)
	if !w.headerWritten {
		w.WriteHeader(200)
	}

	if len(p) != 0 {
		if w.dataStream == nil {
			var err error
			w.dataStream, err = w.session.NewStream(w.dataStreamID)
			if err != nil {
				return 0, fmt.Errorf("error creating data stream: %s\n", err.Error())
			}
		}
		return w.dataStream.Write(p)
	}
	return 0, nil
}

func handleStream(session *quic.Session, headerStream utils.Stream) {
	hpackDecoder := hpack.NewDecoder(4096, nil)
	h2framer := http2.NewFramer(nil, headerStream)

	go func() {
		for {
			if err := handleRequest(session, headerStream, hpackDecoder, h2framer); err != nil {
				fmt.Printf("error handling h2 request: %s\n", err.Error())
				return
			}
		}
	}()
}

func handleRequest(session *quic.Session, headerStream utils.Stream, hpackDecoder *hpack.Decoder, h2framer *http2.Framer) error {
	h2frame, err := h2framer.ReadFrame()
	if err != nil {
		return err
	}
	h2headersFrame := h2frame.(*http2.HeadersFrame)
	if !h2headersFrame.HeadersEnded() {
		return errors.New("http2 header continuation not implemented")
	}
	headers, err := hpackDecoder.DecodeFull(h2headersFrame.HeaderBlockFragment())
	if err != nil {
		fmt.Printf("invalid http2 headers encoding: %s\n", err.Error())
		return err
	}

	req, err := requestFromHeaders(headers)
	if err != nil {
		return err
	}
	fmt.Printf("Request: %#v\n", req)

	responseWriter := &responseWriter{
		header:       http.Header{},
		headerStream: headerStream,
		dataStreamID: protocol.StreamID(h2headersFrame.StreamID),
		session:      session,
	}

	go func() {
		http.DefaultServeMux.ServeHTTP(responseWriter, req)
		if responseWriter.dataStream != nil {
			responseWriter.dataStream.Close()
		}
	}()

	return nil
}

func requestFromHeaders(headers []hpack.HeaderField) (*http.Request, error) {
	var path, authority, method string
	httpHeaders := http.Header{}

	for _, h := range headers {
		switch h.Name {
		case ":path":
			path = h.Value
		case ":method":
			method = h.Value
		case ":authority":
			authority = h.Value
		default:
			if !h.IsPseudo() {
				httpHeaders.Add(h.Name, h.Value)
			}
		}
	}

	if len(path) == 0 || len(authority) == 0 || len(method) == 0 {
		return nil, errors.New(":path, :authority and :method must not be empty")
	}

	u, err := url.Parse(path)
	if err != nil {
		return nil, err
	}

	return &http.Request{
		Method:     method,
		URL:        u,
		Proto:      "HTTP/2.0",
		ProtoMajor: 2,
		ProtoMinor: 0,
		Header:     httpHeaders,
		Body:       nil,
		// ContentLength: -1,
		Host:       authority,
		RequestURI: path,
	}, nil
}
