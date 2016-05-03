package h2quic

import (
	"bytes"
	"fmt"
	"net/http"
	"strconv"

	"github.com/lucas-clemente/quic-go"
	"github.com/lucas-clemente/quic-go/protocol"
	"github.com/lucas-clemente/quic-go/utils"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

type responseWriter struct {
	session      *quic.Session
	dataStreamID protocol.StreamID
	headerStream utils.Stream
	dataStream   utils.Stream

	header        http.Header
	headerWritten bool
}

func newResponseWriter(headerStream utils.Stream, dataStreamID protocol.StreamID, session *quic.Session) *responseWriter {
	return &responseWriter{
		header:       http.Header{},
		headerStream: headerStream,
		dataStreamID: dataStreamID,
		session:      session,
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

	fmt.Printf("Responding with %d %#v\n", status, w.header)
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
