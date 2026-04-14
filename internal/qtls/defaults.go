// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package qtls

import (
	"slices"
	_ "unsafe" // for linkname
)

// Defaults are collected in this file to allow distributions to more easily patch
// them to apply local policies.

var tlsmlkem = newGodebug("tlsmlkem")

// defaultCurvePreferences is the default set of supported key exchanges, as
// well as the preference order.
func defaultCurvePreferences() []CurveID {
	if tlsmlkem.Value() == "0" {
		return []CurveID{X25519, CurveP256, CurveP384, CurveP521}
	}
	return []CurveID{X25519MLKEM768, X25519, CurveP256, CurveP384, CurveP521}
}

// defaultSupportedSignatureAlgorithms returns the signature and hash algorithms that
// the code advertises and supports in a TLS 1.2+ ClientHello and in a TLS 1.2+
// CertificateRequest. The two fields are merged to match with TLS 1.3.
// Note that in TLS 1.2, the ECDSA algorithms are not constrained to P-256, etc.
func defaultSupportedSignatureAlgorithms() []SignatureScheme {
	return []SignatureScheme{
		// Hybrid composite signatures (Ed25519 + ML-DSA, highest priority)
		HybridEd25519MLDSA65, // Hybrid 192-bit (recommended)
		HybridEd25519MLDSA87, // Hybrid 256-bit
		HybridEd25519MLDSA44, // Hybrid 128-bit
		// Post-Quantum ML-DSA signatures (prioritized for quantum resistance)
		MLDSA65, // ML-DSA-65 (192-bit, recommended)
		MLDSA87, // ML-DSA-87 (256-bit, high security)
		MLDSA44, // ML-DSA-44 (128-bit)
		// Classical signatures
		PSSWithSHA256,
		ECDSAWithP256AndSHA256,
		Ed25519,
		PSSWithSHA384,
		PSSWithSHA512,
		PKCS1WithSHA256,
		PKCS1WithSHA384,
		PKCS1WithSHA512,
		ECDSAWithP384AndSHA384,
		ECDSAWithP521AndSHA512,
		PKCS1WithSHA1,
		ECDSAWithSHA1,
	}
}

var tlsrsakex = newGodebug("tlsrsakex")
var tls3des = newGodebug("tls3des")

func supportedCipherSuites(aesGCMPreferred bool) []uint16 {
	if aesGCMPreferred {
		return slices.Clone(cipherSuitesPreferenceOrder)
	} else {
		return slices.Clone(cipherSuitesPreferenceOrderNoAES)
	}
}

func defaultCipherSuites(aesGCMPreferred bool) []uint16 {
	cipherSuites := supportedCipherSuites(aesGCMPreferred)
	return slices.DeleteFunc(cipherSuites, func(c uint16) bool {
		return disabledCipherSuites[c] ||
			tlsrsakex.Value() != "1" && rsaKexCiphers[c] ||
			tls3des.Value() != "1" && tdesCiphers[c]
	})
}

// defaultCipherSuitesTLS13 is also the preference order, since there are no
// disabled by default TLS 1.3 cipher suites. The same AES vs ChaCha20 logic as
// cipherSuitesPreferenceOrder applies.
//
// defaultCipherSuitesTLS13 should be an internal detail,
// but widely used packages access it using linkname.
// Notable members of the hall of shame include:
//   - github.com/quic-go/quic-go
//   - github.com/sagernet/quic-go
//
// Do not remove or change the type signature.
// See go.dev/issue/67401.
//
//go:linkname defaultCipherSuitesTLS13
var defaultCipherSuitesTLS13 = []uint16{
	TLS_AES_128_GCM_SHA256,
	TLS_AES_256_GCM_SHA384,
	TLS_CHACHA20_POLY1305_SHA256,
}

// defaultCipherSuitesTLS13NoAES should be an internal detail,
// but widely used packages access it using linkname.
// Notable members of the hall of shame include:
//   - github.com/quic-go/quic-go
//   - github.com/sagernet/quic-go
//
// Do not remove or change the type signature.
// See go.dev/issue/67401.
//
//go:linkname defaultCipherSuitesTLS13NoAES
var defaultCipherSuitesTLS13NoAES = []uint16{
	TLS_CHACHA20_POLY1305_SHA256,
	TLS_AES_128_GCM_SHA256,
	TLS_AES_256_GCM_SHA384,
}
