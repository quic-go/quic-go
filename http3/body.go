package http3

import (
	"fmt"
	"io"
	"net/http"

	"github.com/lucas-clemente/quic-go"
	"github.com/marten-seemann/qpack"
)

// The body of a http.Request or http.Response.
type body struct {
	str quic.Stream

	isRequest bool

	// only set for the http.Response
	// The channel is closed when the user is done with this response:
	// either when Read() errors, or when Close() is called.
	reqDone       chan<- struct{}
	reqDoneClosed bool

	onFrameError func()

	bytesRemainingInFrame uint64

	resp *http.Response
}

var _ io.ReadCloser = &body{}

func newRequestBody(str quic.Stream, onFrameError func()) *body {
	return &body{
		str:          str,
		onFrameError: onFrameError,
		isRequest:    true,
	}
}

func newResponseBody(str quic.Stream, done chan<- struct{}, onFrameError func(), resp *http.Response) *body {
	return &body{
		str:          str,
		onFrameError: onFrameError,
		reqDone:      done,
		resp:         resp,
	}
}

func (r *body) Read(b []byte) (int, error) {
	n, err := r.readImpl(b)
	if err != nil && !r.isRequest {
		r.requestDone()
	}
	return n, err
}

func (r *body) readImpl(b []byte) (int, error) {
	if r.bytesRemainingInFrame == 0 {
	parseLoop:
		for {
			frame, err := parseNextFrame(r.str)
			if err != nil {
				return 0, err
			}
			switch f := frame.(type) {
			case *headersFrame:
				decoder := qpack.NewDecoder(func(f qpack.HeaderField) {
					if r.resp.Trailer == nil {
						r.resp.Trailer = http.Header{}
					}
					r.resp.Trailer.Add(f.Name, f.Value)
				})

				p := make([]byte, f.Length)
				r.str.Read(p)
				_, err := decoder.Write(p)
				if err != nil {
					// Ignoring invalid frame
					continue
				}
				decoder.Close()
				continue
			case *dataFrame:
				r.bytesRemainingInFrame = f.Length
				break parseLoop
			default:
				r.onFrameError()
				// parseNextFrame skips over unknown frame types
				// Therefore, this condition is only entered when we parsed another known frame type.
				return 0, fmt.Errorf("peer sent an unexpected frame: %T", f)
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

func (r *body) requestDone() {
	if r.reqDoneClosed {
		return
	}
	close(r.reqDone)
	r.reqDoneClosed = true
}

func (r *body) Close() error {
	// quic.Stream.Close() closes the write side, not the read side
	if r.isRequest {
		return r.str.Close()
	}
	r.requestDone()
	r.str.CancelRead(quic.ErrorCode(errorRequestCanceled))
	return nil
}
