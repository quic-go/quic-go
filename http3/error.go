package http3

import (
	"errors"
	"fmt"

	"github.com/quic-go/quic-go"
)

// Error is returned, possibly wrapped, by [Stream] and [RequestStream] operations,
// [ClientConn.OpenRequestStream], [Transport.RoundTrip], [Transport.RoundTripOpt], and
// [ClientConn.RoundTrip] for HTTP clients, and from request-body reads and response
// writes inside HTTP handlers for HTTP servers, when an HTTP/3 error occurs.
// See section 8 of RFC 9114.
type Error struct {
	Remote       bool
	ErrorCode    ErrCode
	ErrorMessage string
}

var _ error = &Error{}

func (e *Error) Error() string {
	s := e.ErrorCode.string()
	if s == "" {
		s = fmt.Sprintf("H3 error (%#x)", uint64(e.ErrorCode))
	}
	// Usually errors are remote. Only make it explicit for local errors.
	if !e.Remote {
		s += " (local)"
	}
	if e.ErrorMessage != "" {
		s += ": " + e.ErrorMessage
	}
	return s
}

func (e *Error) Is(target error) bool {
	t, ok := target.(*Error)
	return ok && e.ErrorCode == t.ErrorCode && e.Remote == t.Remote
}

func maybeReplaceError(err error) error {
	if err == nil {
		return nil
	}

	var (
		e      Error
		strErr *quic.StreamError
		appErr *quic.ApplicationError
	)
	switch {
	default:
		return err
	case errors.As(err, &strErr):
		e.Remote = strErr.Remote
		e.ErrorCode = ErrCode(strErr.ErrorCode)
	case errors.As(err, &appErr):
		e.Remote = appErr.Remote
		e.ErrorCode = ErrCode(appErr.ErrorCode)
		e.ErrorMessage = appErr.ErrorMessage
	}
	var cause error
	if strErr != nil {
		cause = strErr
	} else {
		cause = appErr
	}
	return &errorWithCause{err: &e, cause: cause}
}

type errorWithCause struct {
	err   *Error
	cause error
}

func (e *errorWithCause) Error() string        { return e.err.Error() }
func (e *errorWithCause) Unwrap() error        { return e.cause }
func (e *errorWithCause) Is(target error) bool { return e.err.Is(target) }
func (e *errorWithCause) As(target any) bool {
	t, ok := target.(**Error)
	if ok {
		*t = e.err
	}
	return ok
}
