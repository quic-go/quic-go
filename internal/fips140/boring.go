//go:build boringcrypto

package fips140

import "crypto/boring"

// Enabled reports whether the cryptography libraries are operating in FIPS
// 140-3 mode.
func Enabled() bool {
	return boring.Enabled()
}
