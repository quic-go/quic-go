package handshake

import (
	"crypto/subtle"
	"errors"
	"time"

	"github.com/lucas-clemente/quic-go/crypto"
)

// An STKGenerator generates STKs
type STKGenerator struct {
	stkSource crypto.StkSource
}

// NewSTKGenerator initializes a new STKGenerator
func NewSTKGenerator() (*STKGenerator, error) {
	stkSource, err := crypto.NewStkSource()
	if err != nil {
		return nil, err
	}
	return &STKGenerator{
		stkSource: stkSource,
	}, nil
}

// NewToken generates a new STK token for a given source address
func (g *STKGenerator) NewToken(sourceAddr []byte) ([]byte, error) {
	return g.stkSource.NewToken(sourceAddr)
}

// VerifyToken verifies an STK token
func (g *STKGenerator) VerifyToken(sourceAddr []byte, data []byte) (time.Time, error) {
	tokenAddr, timestamp, err := g.stkSource.DecodeToken(data)
	if err != nil {
		return time.Time{}, err
	}
	if subtle.ConstantTimeCompare(sourceAddr, tokenAddr) != 1 {
		return time.Time{}, errors.New("invalid source address in STK")
	}
	return timestamp, nil
}
