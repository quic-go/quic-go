package http3

import (
	"errors"
	"fmt"
	"net"
	"testing"

	"github.com/quic-go/quic-go"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestErrorConversion(t *testing.T) {
	resetErr := &quic.StatelessResetError{}
	tests := []struct {
		name     string
		input    error
		expected error
	}{
		{name: "nil error", input: nil, expected: nil},
		{name: "regular error", input: assert.AnError, expected: assert.AnError},
		{name: "stateless reset", input: resetErr, expected: resetErr},
		{
			name:     "stream error",
			input:    &quic.StreamError{ErrorCode: 1337, Remote: true},
			expected: &Error{Remote: true, ErrorCode: 1337},
		},
		{
			name:     "application error",
			input:    &quic.ApplicationError{ErrorCode: 42, Remote: true, ErrorMessage: "foobar"},
			expected: &Error{Remote: true, ErrorCode: 42, ErrorMessage: "foobar"},
		},
		{
			name:     "transport error",
			input:    &quic.TransportError{ErrorCode: 42, Remote: true, ErrorMessage: "foobar"},
			expected: &quic.TransportError{ErrorCode: 42, Remote: true, ErrorMessage: "foobar"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.input == nil {
				require.NoError(t, maybeReplaceError(nil))
				return
			}
			for _, input := range []error{tt.input, fmt.Errorf("wrapped: %w", tt.input)} {
				result := maybeReplaceError(input)
				require.ErrorIs(t, result, tt.expected)
				// Converted errors must wrap the original input, including any wrappers.
				// Other errors must be returned unchanged.
				if _, ok := errors.AsType[*Error](tt.expected); ok {
					require.Same(t, input, errors.Unwrap(result))
				} else {
					require.Same(t, input, result)
				}
				require.Equal(t, errors.Is(input, net.ErrClosed), errors.Is(result, net.ErrClosed))
				wrapped := fmt.Errorf("wrapped: %w", result)
				require.Same(t, wrapped, maybeReplaceError(wrapped))
			}
		})
	}
}

func TestErrorString(t *testing.T) {
	tests := []struct {
		name     string
		err      *Error
		expected string
	}{
		{
			name:     "remote error",
			err:      &Error{ErrorCode: 0x10c, Remote: true},
			expected: "H3_REQUEST_CANCELLED",
		},
		{
			name:     "remote error with message",
			err:      &Error{ErrorCode: 0x10c, Remote: true, ErrorMessage: "foobar"},
			expected: "H3_REQUEST_CANCELLED: foobar",
		},
		{
			name:     "local error",
			err:      &Error{ErrorCode: 0x10c, Remote: false},
			expected: "H3_REQUEST_CANCELLED (local)",
		},
		{
			name:     "local error with message",
			err:      &Error{ErrorCode: 0x10c, Remote: false, ErrorMessage: "foobar"},
			expected: "H3_REQUEST_CANCELLED (local): foobar",
		},
		{
			name:     "unknown error code",
			err:      &Error{ErrorCode: 0x1337, Remote: true},
			expected: "H3 error (0x1337)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.expected, tt.err.Error())
		})
	}
}
