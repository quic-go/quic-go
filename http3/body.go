package http3

import (
	"errors"
	"io"
)

// The body of a http.Request or http.Response.
type body struct {
	str io.ReadCloser

	isRequest bool

	bytesRemainingInFrame uint64
}

var _ io.ReadCloser = &body{}

func newRequestBody(str io.ReadCloser) *body {
	return &body{
		str:       str,
		isRequest: true,
	}
}

func newResponseBody(str io.ReadCloser) *body {
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
		return nil
	}
	return r.str.Close()
}
