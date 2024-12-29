package quic

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestStreamError(t *testing.T) {
	require.True(t, errors.Is(
		&StreamError{StreamID: 1, ErrorCode: 2, Remote: true},
		&StreamError{StreamID: 1, ErrorCode: 2, Remote: true},
	))
	require.False(t, errors.Is(&StreamError{StreamID: 1}, &StreamError{StreamID: 2}))
	require.False(t, errors.Is(&StreamError{StreamID: 1}, &StreamError{StreamID: 2}))
	require.Equal(t,
		"stream 1 canceled by remote with error code 2",
		(&StreamError{StreamID: 1, ErrorCode: 2, Remote: true}).Error(),
	)
	require.Equal(t,
		"stream 42 canceled by local with error code 1337",
		(&StreamError{StreamID: 42, ErrorCode: 1337, Remote: false}).Error(),
	)
}

func TestDatagramTooLargeError(t *testing.T) {
	require.True(t, errors.Is(
		&DatagramTooLargeError{MaxDatagramPayloadSize: 1024},
		&DatagramTooLargeError{MaxDatagramPayloadSize: 1024},
	))
	require.False(t, errors.Is(
		&DatagramTooLargeError{MaxDatagramPayloadSize: 1024},
		&DatagramTooLargeError{MaxDatagramPayloadSize: 1025},
	))
	require.Equal(t, "DATAGRAM frame too large", (&DatagramTooLargeError{MaxDatagramPayloadSize: 1024}).Error())
}
