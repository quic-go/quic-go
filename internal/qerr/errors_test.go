package qerr

import (
	"errors"
	"fmt"
	"net"
	"testing"

	"github.com/quic-go/quic-go/internal/protocol"
)

type myError int

var _ error = myError(0)

func (e myError) Error() string { return fmt.Sprintf("my error %d", e) }

func TestQUICErrors(t *testing.T) {
	t.Run("Transport", func(t *testing.T) {
		t.Run("Error", func(t *testing.T) {
			got := (&TransportError{
				ErrorCode:    FlowControlError,
				ErrorMessage: "foobar",
			}).Error()
			const want = "FLOW_CONTROL_ERROR (local): foobar"
			if got != want {
				t.Errorf("unexpected error string: got: %q, want: %q", got, want)
			}
		})

		t.Run("EmptyErrorPhrase", func(t *testing.T) {
			got := (&TransportError{ErrorCode: FlowControlError}).Error()
			const want = "FLOW_CONTROL_ERROR (local)"
			if got != want {
				t.Errorf("unexpected error string: got: %q, want: %q", got, want)
			}
		})

		t.Run("FrameTypeWithoutMessage", func(t *testing.T) {
			got := (&TransportError{
				Remote:    true,
				ErrorCode: FlowControlError,
				FrameType: 0x1337,
			}).Error()
			const want = "FLOW_CONTROL_ERROR (remote) (frame type: 0x1337)"
			if got != want {
				t.Errorf("unexpected error string: got: %q, want: %q", got, want)
			}
		})

		t.Run("FrameTypeWithMessage", func(t *testing.T) {
			got := (&TransportError{
				ErrorCode:    FlowControlError,
				FrameType:    0x1337,
				ErrorMessage: "foobar",
			}).Error()
			const want = "FLOW_CONTROL_ERROR (local) (frame type: 0x1337): foobar"
			if got != want {
				t.Errorf("unexpected error string: got: %q, want: %q", got, want)
			}
		})

		t.Run("Crypto", func(t *testing.T) {
			t.Run("WithMessage", func(t *testing.T) {
				myErr := myError(1337)
				err := NewLocalCryptoError(0x42, myErr)
				got := err.Error()
				const want = "CRYPTO_ERROR 0x142 (local): my error 1337"
				if got != want {
					t.Errorf("unexpected error string: got: %q, want: %q", got, want)
				}
			})

			t.Run("Unwraps", func(t *testing.T) {
				var myErr myError
				err := NewLocalCryptoError(0x42, myError(1337))
				if !errors.As(err, &myErr) {
					t.Errorf("failed to unwrap")
				}
				if got, want := int(myErr), 1337; got != want {
					t.Errorf("unwrapped incorrectly: got: %d, want: %d", got, want)
				}
			})

			t.Run("WithoutMessage", func(t *testing.T) {
				err := NewLocalCryptoError(0x2a, nil)
				got := err.Error()
				const want = "CRYPTO_ERROR 0x12a (local): tls: bad certificate"
				if got != want {
					t.Errorf("unexpected error string: got: %q, want: %q", got, want)
				}
			})
		})
	})

	t.Run("Application", func(t *testing.T) {
		t.Run("WithMessage", func(t *testing.T) {
			got := (&ApplicationError{
				ErrorCode:    0x42,
				ErrorMessage: "foobar",
			}).Error()
			const want = "Application error 0x42 (local): foobar"
			if got != want {
				t.Errorf("unexpected error string: got: %q, want: %q", got, want)
			}
		})

		t.Run("WithoutMessage", func(t *testing.T) {
			got := (&ApplicationError{
				ErrorCode: 0x42,
				Remote:    true,
			}).Error()
			const want = "Application error 0x42 (remote)"
			if got != want {
				t.Errorf("unexpected error string: got: %q, want: %q", got, want)
			}
		})
	})

	t.Run("Timeout", func(t *testing.T) {
		t.Run("Handshake", func(t *testing.T) {
			//nolint:gosimple // we need to assign to an interface here
			var err error
			err = &HandshakeTimeoutError{}
			nerr, ok := err.(net.Error)
			if !ok {
				t.Fatal("failed assertion to net.Error")
			}
			if !nerr.Timeout() {
				t.Error(`(net.Error).Timeout() reported "false"`)
			}
			if got, want := err.Error(), "timeout: handshake did not complete in time"; got != want {
				t.Errorf("unexpected error string: got: %q, want: %q", got, want)
			}
		})

		t.Run("Idle", func(t *testing.T) {
			//nolint:gosimple // we need to assign to an interface here
			var err error
			err = &IdleTimeoutError{}
			nerr, ok := err.(net.Error)
			if !ok {
				t.Fatal("failed assertion to net.Error")
			}
			if !nerr.Timeout() {
				t.Error(`(net.Error).Timeout() reported "false"`)
			}
			if got, want := err.Error(), "timeout: no recent network activity"; got != want {
				t.Errorf("unexpected error string: got: %q, want: %q", got, want)
			}
		})
	})

	t.Run("VersionNegotiation", func(t *testing.T) {
		t.Run("Error", func(t *testing.T) {
			got := (&VersionNegotiationError{
				Ours:   []protocol.VersionNumber{2, 3},
				Theirs: []protocol.VersionNumber{4, 5, 6},
			}).Error()
			const want = "no compatible QUIC version found (we support [0x2 0x3], server offered [0x4 0x5 0x6])"
			if got != want {
				t.Errorf("unexpected error string: got: %q, want: %q", got, want)
			}
		})
	})

	t.Run("StatelessReset", func(t *testing.T) {
		token := protocol.StatelessResetToken{0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf}

		t.Run("Error", func(t *testing.T) {
			got := (&StatelessResetError{Token: token}).Error()
			const want = "received a stateless reset with token 000102030405060708090a0b0c0d0e0f"
			if got != want {
				t.Errorf("unexpected error string: got: %q, want: %q", got, want)
			}
		})

		t.Run("net.Error", func(t *testing.T) {
			//nolint:gosimple // we need to assign to an interface here
			var err error
			err = &StatelessResetError{}
			nerr, ok := err.(net.Error)
			if !ok {
				t.Fatal("failed assertion to net.Error")
			}
			if nerr.Timeout() {
				t.Error(`(net.Error).Timeout() reported "true"`)
			}
		})
	})

	t.Run("ErrClosed", func(t *testing.T) {
		errs := []error{
			&TransportError{},
			&ApplicationError{},
			&IdleTimeoutError{},
			&HandshakeTimeoutError{},
			&StatelessResetError{},
			&VersionNegotiationError{},
		}
		for _, err := range errs {
			if !errors.Is(err, net.ErrClosed) {
				t.Errorf("errors.Is(%T, net.ErrClosed) != true", err)
			}
		}
	})
}
