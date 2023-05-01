//go:build go1.19 && !go1.20

package self_test

import (
	"errors"
	"net/http"
	"time"
)

var (
	go120           = false
	errNotSupported = errors.New("not supported")
)

func setReadDeadline(w http.ResponseWriter, deadline time.Time) error {
	return errNotSupported
}

func setWriteDeadline(w http.ResponseWriter, deadline time.Time) error {
	return errNotSupported
}
