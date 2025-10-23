//go:build !go1.25

package self_test

import "crypto/tls"

func getCurveID(connState tls.ConnectionState) tls.CurveID {
	return 0
}
