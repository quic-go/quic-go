// +build go1.15

package quic

import (
	"os"
)

func (deadlineError) Unwrap() error { return os.ErrDeadlineExceeded }
