package qerr

import (
	"fmt"
)

// ErrorCode can be used as a normal error without reason.
type ErrorCode uint32

func (e ErrorCode) Error() string {
	return e.String()
}

// A QuicError consists of an error code plus a error reason
type QuicError struct {
	ErrorCode    ErrorCode
	ErrorMessage string
}

// Error creates a new QuicError instance
func Error(errorCode ErrorCode, errorMessage string) *QuicError {
	return &QuicError{
		ErrorCode:    errorCode,
		ErrorMessage: errorMessage,
	}
}

func (e *QuicError) Error() string {
	return fmt.Sprintf("%s: %s", e.ErrorCode.String(), e.ErrorMessage)
}
