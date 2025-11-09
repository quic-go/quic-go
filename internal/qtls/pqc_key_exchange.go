// Copyright 2024 The quic-go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package qtls

import (
	"errors"
	"io"

	"github.com/quic-go/quic-go/internal/handshake/pqc"
)

// pqcKeyShare holds a PQC key exchange instance
type pqcKeyShare struct {
	curveID  CurveID
	keyEx    pqc.KeyExchange
	provider pqc.CryptoProvider
}

// generatePQCKeyShare generates a PQC key share for the given curve ID
func generatePQCKeyShare(rand io.Reader, curveID CurveID) (*pqcKeyShare, error) {
	var provider pqc.CryptoProvider

	switch curveID {
	case MLKEM768:
		provider = pqc.NewMLKEM768Provider()
	case MLKEM1024:
		provider = pqc.NewMLKEM1024Provider()
	default:
		return nil, errors.New("qtls: unsupported PQC curve ID")
	}

	keyEx, err := provider.GenerateKeyPair()
	if err != nil {
		return nil, err
	}

	return &pqcKeyShare{
		curveID:  curveID,
		keyEx:    keyEx,
		provider: provider,
	}, nil
}

// PublicKey returns the public key bytes for this key share
func (ks *pqcKeyShare) PublicKey() []byte {
	return ks.keyEx.PublicKey()
}

// DeriveSharedSecret derives the shared secret from the peer's public key
func (ks *pqcKeyShare) DeriveSharedSecret(peerPublicKey []byte, isClient bool) ([]byte, error) {
	return ks.keyEx.DeriveSharedSecret(peerPublicKey, isClient)
}

// isPurePQCCurve checks if the curve is a pure PQC algorithm (not hybrid)
func isPurePQCCurve(id CurveID) bool {
	return id == MLKEM768 || id == MLKEM1024
}

// pqcServerResponse holds the server's PQC key exchange response
type pqcServerResponse struct {
	sharedSecret []byte
	ciphertext   []byte
}

// processPQCClientKeyShare processes a client's PQC public key and generates the server's response
func processPQCClientKeyShare(curveID CurveID, clientPublicKey []byte, rand io.Reader) (*pqcServerResponse, error) {
	var provider pqc.CryptoProvider

	switch curveID {
	case MLKEM768:
		provider = pqc.NewMLKEM768Provider()
	case MLKEM1024:
		provider = pqc.NewMLKEM1024Provider()
	default:
		return nil, errors.New("qtls: unsupported PQC curve ID")
	}

	// Server generates a key exchange instance (won't actually use its own keys for KEM)
	keyEx, err := provider.GenerateKeyPair()
	if err != nil {
		return nil, err
	}

	// Server encapsulates using client's public key (isClient=false for server side)
	sharedSecret, err := keyEx.DeriveSharedSecret(clientPublicKey, false)
	if err != nil {
		return nil, err
	}

	// Get the ciphertext that was generated during encapsulation
	ciphertext := keyEx.PublicKey()

	return &pqcServerResponse{
		sharedSecret: sharedSecret,
		ciphertext:   ciphertext,
	}, nil
}
