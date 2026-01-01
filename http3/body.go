package http3

import (
	"context"
	"errors"
	"io"
	"sync"

	"github.com/quic-go/quic-go"
)

// Settingser allows waiting for and retrieving the peer's HTTP/3 settings.
type Settingser interface {
	// ReceivedSettings returns a channel that is closed once the peer's SETTINGS frame was received.
	// Settings can be obtained from the Settings method after the channel was closed.
	ReceivedSettings() <-chan struct{}
	// Settings returns the settings received on this connection.
	// It is only valid to call this function after the channel returned by ReceivedSettings was closed.
	Settings() *Settings
}

var errTooMuchData = errors.New("peer sent too much data")

// The body is used in the requestBody (for a http.Request) and the responseBody (for a http.Response).
type body struct {
	str *Stream

	remainingContentLength int64
	violatedContentLength  bool
	hasContentLength       bool
}

func newBody(str *Stream, contentLength int64) *body {
	b := &body{str: str}
	if contentLength >= 0 {
		b.hasContentLength = true
		b.remainingContentLength = contentLength
	}
	return b
}

func (r *body) StreamID() quic.StreamID { return r.str.StreamID() }

func (r *body) checkContentLengthViolation() error {
	if !r.hasContentLength {
		return nil
	}
	if r.remainingContentLength < 0 || r.remainingContentLength == 0 && r.str.hasMoreData() {
		if !r.violatedContentLength {
			r.str.CancelRead(quic.StreamErrorCode(ErrCodeMessageError))
			r.str.CancelWrite(quic.StreamErrorCode(ErrCodeMessageError))
			r.violatedContentLength = true
		}
		return errTooMuchData
	}
	return nil
}

func (r *body) Read(b []byte) (int, error) {
	if err := r.checkContentLengthViolation(); err != nil {
		return 0, err
	}
	if r.hasContentLength {
		b = b[:min(int64(len(b)), r.remainingContentLength)]
	}
	n, err := r.str.Read(b)
	r.remainingContentLength -= int64(n)
	if err := r.checkContentLengthViolation(); err != nil {
		return n, err
	}
	return n, maybeReplaceError(err)
}

func (r *body) Close() error {
	r.str.CancelRead(quic.StreamErrorCode(ErrCodeRequestCanceled))
	return nil
}

type requestBody struct {
	body
	connCtx      context.Context
	rcvdSettings <-chan struct{}
	getSettings  func() *Settings
}

var _ io.ReadCloser = &requestBody{}

func newRequestBody(str *Stream, contentLength int64, connCtx context.Context, rcvdSettings <-chan struct{}, getSettings func() *Settings) *requestBody {
	return &requestBody{
		body:         *newBody(str, contentLength),
		connCtx:      connCtx,
		rcvdSettings: rcvdSettings,
		getSettings:  getSettings,
	}
}

type hijackableBody struct {

	body body



	// only set for the http.Response

	// The channel is closed when the user is done with this response:

	// either when Read() errors, or when Close() is called.

	reqDone     chan<- struct{}

	reqDoneOnce sync.Once



	mu                     sync.Mutex

	ctx                    context.Context

	dontCloseRequestStream bool



		// closed when Close() is called



		bodyClosed     chan struct{}



		bodyClosedOnce sync.Once



		monitorOnce    sync.Once



	}



	



	var _ io.ReadCloser = &hijackableBody{}



	



	func newResponseBody(str *Stream, contentLength int64, done chan<- struct{}) *hijackableBody {



		return &hijackableBody{



			body:       *newBody(str, contentLength),



			reqDone:    done,



			bodyClosed: make(chan struct{}),



		}



	}



	



	func (r *hijackableBody) setContext(ctx context.Context, dontClose bool) {



		r.mu.Lock()



		r.ctx = ctx



		r.dontCloseRequestStream = dontClose



		r.mu.Unlock()



	



		if dontClose {



			return



		}



	



		r.monitorOnce.Do(func() {



			go func() {



				select {



				case <-ctx.Done():



					r.mu.Lock()



					// Check again in case setContext was called again (unlikely) or dontClose changed



					if !r.dontCloseRequestStream {



						r.body.str.CancelRead(quic.StreamErrorCode(ErrCodeRequestCanceled))



					}



					r.mu.Unlock()



				case <-r.bodyClosed:



				}



			}()



		})



	}



	



	func (r *hijackableBody) Read(b []byte) (int, error) {



		r.mu.Lock()



		ctx := r.ctx



		dontClose := r.dontCloseRequestStream



		r.mu.Unlock()



	



		if !dontClose && ctx != nil {



			select {



			case <-ctx.Done():



				return 0, ctx.Err()



			default:



			}



		}



		n, err := r.body.Read(b)



		if err != nil {



			r.requestDone()



		}



		if n == 0 && err != nil && !dontClose && ctx != nil && ctx.Err() != nil {



			return 0, ctx.Err()



		}



		return n, maybeReplaceError(err)



	}



	



func (r *hijackableBody) requestDone() {

	if r.reqDone != nil {

		r.reqDoneOnce.Do(func() {

			close(r.reqDone)

		})

	}

}



func (r *hijackableBody) Close() error {

	r.bodyClosedOnce.Do(func() {

		close(r.bodyClosed)

	})

	r.requestDone()

	// If the EOF was read, CancelRead() is a no-op.

	r.body.str.CancelRead(quic.StreamErrorCode(ErrCodeRequestCanceled))

	return nil

}
