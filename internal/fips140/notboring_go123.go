//go:build !boringcrypto && !go1.24

package fips140

// Enabled reports whether the cryptography libraries are operating in FIPS
// 140-3 mode.
func Enabled() bool {
	return false
}
