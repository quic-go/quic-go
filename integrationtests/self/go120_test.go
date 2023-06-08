//go:build go1.20

package self_test

import (
	"net/http"
	"time"
)

const go120 = true

func setReadDeadline(w http.ResponseWriter, deadline time.Time) error {
	rc := http.NewResponseController(w)

	return rc.SetReadDeadline(deadline)
}

func setWriteDeadline(w http.ResponseWriter, deadline time.Time) error {
	rc := http.NewResponseController(w)

	return rc.SetWriteDeadline(deadline)
}
