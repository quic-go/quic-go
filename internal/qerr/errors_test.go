package qerr

import (
	"errors"
	"fmt"
	"net"
	"testing"

	"github.com/quic-go/quic-go/internal/protocol"

	"github.com/stretchr/testify/require"
)

func TestTransportError(t *testing.T) {
	require.True(t, errors.Is(&TransportError{}, net.ErrClosed))

	require.True(t, errors.Is(
		&TransportError{Remote: true, ErrorCode: 1, FrameType: 2},
		&TransportError{Remote: true, ErrorCode: 1, FrameType: 2},
	))
	require.True(t, errors.Is(&TransportError{ErrorCode: 0x101}, &TransportError{ErrorCode: 0x101}))
	require.False(t, errors.Is(&TransportError{}, &TransportError{ErrorCode: 0x101}))
	require.False(t, errors.Is(&TransportError{}, &TransportError{FrameType: 0x1337}))
	require.False(t, errors.Is(&TransportError{Remote: false}, &TransportError{Remote: true}))
}

func TestTransportErrorStringer(t *testing.T) {
	t.Run("with error message", func(t *testing.T) {
		err := &TransportError{
			ErrorCode:    FlowControlError,
			ErrorMessage: "foobar",
		}
		require.Equal(t, "FLOW_CONTROL_ERROR (local): foobar", err.Error())
	})

	t.Run("without error message", func(t *testing.T) {
		err := &TransportError{ErrorCode: FlowControlError}
		require.Equal(t, "FLOW_CONTROL_ERROR (local)", err.Error())
	})

	t.Run("with frame type", func(t *testing.T) {
		err := &TransportError{
			Remote:    true,
			ErrorCode: FlowControlError,
			FrameType: 0x1337,
		}
		require.Equal(t, "FLOW_CONTROL_ERROR (remote) (frame type: 0x1337)", err.Error())
	})

	t.Run("with frame type and error message", func(t *testing.T) {
		err := &TransportError{
			ErrorCode:    FlowControlError,
			FrameType:    0x1337,
			ErrorMessage: "foobar",
		}
		require.Equal(t, "FLOW_CONTROL_ERROR (local) (frame type: 0x1337): foobar", err.Error())
	})
}

type myError int

var _ error = myError(0)

func (e myError) Error() string { return fmt.Sprintf("my error %d", e) }

func TestCryptoError(t *testing.T) {
	var myErr myError
	err := NewLocalCryptoError(0x42, myError(1337))
	require.True(t, errors.As(err, &myErr))
	require.Equal(t, myError(1337), myErr)

	testErr := errors.New("test error")
	err = NewLocalCryptoError(0x42, testErr)
	require.True(t, errors.Is(err, testErr))
	require.True(t, errors.Is(
		NewLocalCryptoError(0x42, testErr),
		NewLocalCryptoError(0x42, testErr),
	))
	require.False(t, errors.Is(
		NewLocalCryptoError(0x42, testErr),
		NewLocalCryptoError(0x43, testErr),
	))
}

func TestCryptoErrorStringer(t *testing.T) {
	t.Run("with error message", func(t *testing.T) {
		myErr := myError(1337)
		err := NewLocalCryptoError(0x42, myErr)
		require.Equal(t, "CRYPTO_ERROR 0x142 (local): my error 1337", err.Error())
	})

	t.Run("without error message", func(t *testing.T) {
		err := NewLocalCryptoError(0x2a, nil)
		require.Equal(t, "CRYPTO_ERROR 0x12a (local): tls: bad certificate", err.Error())
	})
}

func TestApplicationError(t *testing.T) {
	require.True(t, errors.Is(&ApplicationError{}, net.ErrClosed))

	require.True(t, errors.Is(
		&ApplicationError{ErrorCode: 1, Remote: true},
		&ApplicationError{ErrorCode: 1, Remote: true},
	))
	require.True(t, errors.Is(&ApplicationError{ErrorCode: 0x101}, &ApplicationError{ErrorCode: 0x101}))
	require.False(t, errors.Is(&ApplicationError{}, &ApplicationError{ErrorCode: 0x101}))
	require.False(t, errors.Is(&ApplicationError{Remote: false}, &ApplicationError{Remote: true}))
}

func TestApplicationErrorStringer(t *testing.T) {
	t.Run("with error message", func(t *testing.T) {
		err := &ApplicationError{
			ErrorCode:    0x42,
			ErrorMessage: "foobar",
		}
		require.Equal(t, "Application error 0x42 (local): foobar", err.Error())
	})

	t.Run("without error message", func(t *testing.T) {
		err := &ApplicationError{
			ErrorCode: 0x42,
			Remote:    true,
		}
		require.Equal(t, "Application error 0x42 (remote)", err.Error())
	})
}

func TestHandshakeTimeoutError(t *testing.T) {
	require.True(t, errors.Is(&HandshakeTimeoutError{}, &HandshakeTimeoutError{}))
	require.False(t, errors.Is(&HandshakeTimeoutError{}, &IdleTimeoutError{}))

	//nolint:gosimple // we need to assign to an interface here
	var err error
	err = &HandshakeTimeoutError{}
	nerr, ok := err.(net.Error)
	require.True(t, ok)
	require.True(t, nerr.Timeout())
	require.Equal(t, "timeout: handshake did not complete in time", err.Error())
	require.True(t, errors.Is(&HandshakeTimeoutError{}, net.ErrClosed))
}

func TestIdleTimeoutError(t *testing.T) {
	require.True(t, errors.Is(&IdleTimeoutError{}, &IdleTimeoutError{}))
	require.False(t, errors.Is(&IdleTimeoutError{}, &HandshakeTimeoutError{}))

	//nolint:gosimple // we need to assign to an interface here
	var err error
	err = &IdleTimeoutError{}
	nerr, ok := err.(net.Error)
	require.True(t, ok)
	require.True(t, nerr.Timeout())
	require.Equal(t, "timeout: no recent network activity", err.Error())
	require.True(t, errors.Is(&IdleTimeoutError{}, net.ErrClosed))
}

func TestVersionNegotiationErrorString(t *testing.T) {
	err := &VersionNegotiationError{
		Ours:   []protocol.Version{2, 3},
		Theirs: []protocol.Version{4, 5, 6},
	}
	require.Equal(t, "no compatible QUIC version found (we support [0x2 0x3], server offered [0x4 0x5 0x6])", err.Error())
	require.True(t, errors.Is(&VersionNegotiationError{}, net.ErrClosed))
}

func TestStatelessResetError(t *testing.T) {
	require.Equal(t, "received a stateless reset", (&StatelessResetError{}).Error())
	require.True(t, errors.Is(&StatelessResetError{}, &StatelessResetError{}))

	//nolint:gosimple // we need to assign to an interface here
	var err error
	err = &StatelessResetError{}
	nerr, ok := err.(net.Error)
	require.True(t, ok)
	require.False(t, nerr.Timeout())
	require.True(t, errors.Is(&StatelessResetError{}, net.ErrClosed))
}
