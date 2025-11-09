// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// ECH (Encrypted Client Hello) stub for qtls fork
// ECH is not supported - these are minimal stubs to make the code compile

package qtls

import (
	"errors"
	"hash"
)

// HPKE stubs
type hpkeSender struct{}
type hpkeRecipient struct{}

// ECH types - stubs only
type echConfig struct {
	raw                  []byte
	KemID                uint16
	PublicKey            []byte
	PublicName           string
	SymmetricCipherSuite []byte
}

type echCipher uint16

type echClientContext struct {
	config          *echConfig
	hpkeContext     *hpkeSender
	encapsulatedKey []byte
	innerHello      *clientHelloMsg
	innerTranscript hash.Hash
	kdfID           uint16
	aeadID          uint16
	echRejected     bool
	retryConfigs    []byte
}

type echServerContext struct {
	hpkeContext *hpkeRecipient
	configID    uint8
	ciphersuite echCipher
	transcript  hash.Hash
	inner       bool
}

// ECH functions - stubs that return errors
func parseECHConfigList(data []byte) ([]*echConfig, error) {
	return nil, errors.New("ECH not supported in qtls fork")
}

func pickECHConfig(configs []*echConfig) *echConfig {
	return nil
}

func pickECHCipherSuite(suites []byte) (*cipherSuiteTLS13, error) {
	return nil, errors.New("ECH not supported in qtls fork")
}

func parseECHExt(data []byte) (echType byte, echCiphersuite echCipher, configID uint8, encap, payload []byte, err error) {
	err = errors.New("ECH not supported in qtls fork")
	return
}

func computeAndUpdateOuterECHExtension(outer, inner *clientHelloMsg, ech *echClientContext, helloRetryRequest bool) error {
	return errors.New("ECH not supported in qtls fork")
}

func (c *Conn) processECHClientHello(hello *clientHelloMsg, echKeys []EncryptedClientHelloKey) (*clientHelloMsg, *echServerContext, error) {
	return nil, nil, errors.New("ECH not supported in qtls fork")
}

const (
	outerECHExt = 0
	innerECHExt = 1
)

func decryptECHPayload(hpkeContext *hpkeRecipient, original, payload []byte) ([]byte, error) {
	return nil, errors.New("ECH not supported in qtls fork")
}

func decodeInnerClientHello(outer *clientHelloMsg, encoded []byte) (*clientHelloMsg, error) {
	return nil, errors.New("ECH not supported in qtls fork")
}

func buildRetryConfigList(echKeys []EncryptedClientHelloKey) ([]byte, error) {
	return nil, errors.New("ECH not supported in qtls fork")
}

// ECHRejectionError is returned when ECH is rejected
type ECHRejectionError struct {
	RetryConfigList []byte
}

func (e *ECHRejectionError) Error() string {
	return "ech: rejected"
}

// HPKE package stubs
var hpke = struct {
	ParseHPKEPublicKey func(kemID uint16, publicKey []byte) (interface{}, error)
	SetupSender        func(kemID, kdfID, aeadID uint16, publicKey interface{}, info []byte) ([]byte, *hpkeSender, error)
}{
	ParseHPKEPublicKey: func(kemID uint16, publicKey []byte) (interface{}, error) {
		return nil, errors.New("HPKE not supported in qtls fork")
	},
	SetupSender: func(kemID, kdfID, aeadID uint16, publicKey interface{}, info []byte) ([]byte, *hpkeSender, error) {
		return nil, nil, errors.New("HPKE not supported in qtls fork")
	},
}
