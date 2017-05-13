package handshake

import (
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
func (g *STKGenerator) VerifyToken(sourceAddr []byte, token []byte) (time.Time, error) {
	return g.stkSource.VerifyToken(sourceAddr, token)
}
