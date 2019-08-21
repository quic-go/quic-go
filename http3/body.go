package http3

import (
	"errors"
	"io"

	"github.com/lucas-clemente/quic-go"
)

// The body of a http.Request or http.Response.
type body struct {
	str quic.Stream

	isRequest bool

	bytesRemainingInFrame uint64
}

var _ io.ReadCloser = &body{}

func newRequestBody(str quic.Stream) *body {
	return &body{
		str:       str,
		isRequest: true,
	}
}

func newResponseBody(str quic.Stream) *body {
	return &body{str: str}
}

func (r *body) Read(b []byte) (int, error) {
	if r.bytesRemainingInFrame == 0 {
	parseLoop:
		for {
			frame, err := parseNextFrame(r.str)
			if err != nil {
				return 0, err
			}
			switch f := frame.(type) {
			case *headersFrame:
				// skip HEADERS frames
				continue
			case *dataFrame:
				r.bytesRemainingInFrame = f.Length
				break parseLoop
			default:
				return 0, errors.New("unexpected frame")
			}
		}
	}

	var n int
	var err error
	if r.bytesRemainingInFrame < uint64(len(b)) {
		n, err = r.str.Read(b[:r.bytesRemainingInFrame])
	} else {
		n, err = r.str.Read(b)
	}
	r.bytesRemainingInFrame -= uint64(n)
	return n, err
}

func (r *body) Close() error {
	// quic.Stream.Close() closes the write side, not the read side
	if r.isRequest {
		return r.str.Close()
	}
	r.str.CancelRead(quic.ErrorCode(errorRequestCanceled))
	return nil
}
