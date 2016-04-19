package protocol

// A QuicError is a QUIC error
type QuicError struct {
	ErrorCode    ErrorCode
	ErrorMessage string
}

// NewQuicError creates a new Quic Error
func NewQuicError(errorCode ErrorCode, errorMessage string) *QuicError {
	return &QuicError{
		ErrorCode:    errorCode,
		ErrorMessage: errorMessage,
	}
}

func (e *QuicError) Error() string {
	return e.ErrorMessage
}

var _ error = &QuicError{}
