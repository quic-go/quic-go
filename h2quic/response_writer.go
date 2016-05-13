package h2quic

import (
	"bytes"
	"net/http"
	"strconv"

	"github.com/lucas-clemente/quic-go/protocol"
	"github.com/lucas-clemente/quic-go/utils"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

type responseWriter struct {
	dataStreamID protocol.StreamID
	headerStream utils.Stream
	dataStream   utils.Stream

	header        http.Header
	headerWritten bool
}

func newResponseWriter(headerStream, dataStream utils.Stream, dataStreamID protocol.StreamID) *responseWriter {
	return &responseWriter{
		header:       http.Header{},
		headerStream: headerStream,
		dataStream:   dataStream,
		dataStreamID: dataStreamID,
	}
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

	utils.Infof("Responding with %d", status)
	h2framer := http2.NewFramer(w.headerStream, nil)
	err := h2framer.WriteHeaders(http2.HeadersFrameParam{
		StreamID:      uint32(w.dataStreamID),
		EndHeaders:    true,
		BlockFragment: headers.Bytes(),
	})
	if err != nil {
		panic(err)
	}
}

func (w *responseWriter) Write(p []byte) (int, error) {
	if !w.headerWritten {
		w.WriteHeader(200)
	}
	return w.dataStream.Write(p)
}
