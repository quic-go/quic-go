package http3

import (
	"errors"
	"testing"

	"github.com/quic-go/quic-go"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestErrorConversion(t *testing.T) {
	tests := []struct {
		name     string
		input    error
		expected error
	}{
		{name: "nil error", input: nil, expected: nil},
		{name: "regular error", input: assert.AnError, expected: assert.AnError},
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
			result := maybeReplaceError(tt.input)
			if tt.expected == nil {
				require.Nil(t, result)
			} else {
				require.ErrorIs(t, tt.expected, result)
			}
		})
	}
}

func TestErrorConversionPreservesQUICErrorType(t *testing.T) {
	streamErr := &quic.StreamError{ErrorCode: 1337, Remote: true}
	convertedStreamErr := maybeReplaceError(streamErr)
	var gotStreamErr *quic.StreamError
	require.True(t, errors.As(convertedStreamErr, &gotStreamErr))
	require.Same(t, streamErr, gotStreamErr)
	var appErrFromStream *quic.ApplicationError
	require.False(t, errors.As(convertedStreamErr, &appErrFromStream))

	appErr := &quic.ApplicationError{ErrorCode: 42, Remote: true, ErrorMessage: "foobar"}
	convertedAppErr := maybeReplaceError(appErr)
	var gotAppErr *quic.ApplicationError
	require.True(t, errors.As(convertedAppErr, &gotAppErr))
	require.Same(t, appErr, gotAppErr)
	var streamErrFromApp *quic.StreamError
	require.False(t, errors.As(convertedAppErr, &streamErrFromApp))
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
