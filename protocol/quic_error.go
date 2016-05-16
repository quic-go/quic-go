package protocol

import (
	"github.com/lucas-clemente/quic-go/errorcodes"
)

// A QuicError is a QUIC error
type QuicError struct {
	ErrorCode    errorcodes.ErrorCode
	ErrorMessage string
}

// Error creates a new Quic Error
func Error(errorCode errorcodes.ErrorCode, errorMessage string) *QuicError {
	return &QuicError{
		ErrorCode:    errorCode,
		ErrorMessage: errorMessage,
	}
}

func (e *QuicError) Error() string {
	return e.ErrorMessage
}

var _ error = &QuicError{}
