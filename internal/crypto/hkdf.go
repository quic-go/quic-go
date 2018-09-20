package crypto

import (
	"crypto"
	"crypto/hmac"
)

// copied from https://github.com/cloudflare/tls-tris/blob/master/hkdf.go
func hkdfExtract(hash crypto.Hash, secret, salt []byte) []byte {
	if salt == nil {
		salt = make([]byte, hash.Size())
	}
	if secret == nil {
		secret = make([]byte, hash.Size())
	}
	extractor := hmac.New(hash.New, salt)
	extractor.Write(secret)
	return extractor.Sum(nil)
}
