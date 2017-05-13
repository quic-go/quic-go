package handshake

import (
	"bytes"
	"crypto/subtle"
	"errors"
	"net"
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
func (g *STKGenerator) NewToken(raddr net.Addr) ([]byte, error) {
	return g.stkSource.NewToken(encodeRemoteAddr(raddr))
}

// VerifyToken verifies an STK token
func (g *STKGenerator) VerifyToken(raddr net.Addr, data []byte) (time.Time, error) {
	data, timestamp, err := g.stkSource.DecodeToken(data)
	if err != nil {
		return time.Time{}, err
	}
	if subtle.ConstantTimeCompare(encodeRemoteAddr(raddr), data) != 1 {
		return time.Time{}, errors.New("invalid source address in STK")
	}
	return timestamp, nil
}

// encodeRemoteAddr encodes a remote address such that it can be saved in the STK
// it ensures that we're binary compatible with Google's implementation of STKs
func encodeRemoteAddr(remoteAddr net.Addr) []byte {
	// if the address is a UDP address, just use the byte representation of the IP address
	// the length of an IP address is 4 bytes (for IPv4) or 16 bytes (for IPv6)
	if udpAddr, ok := remoteAddr.(*net.UDPAddr); ok {
		return udpAddr.IP
	}
	// if the address is not a UDP address, prepend 16 bytes
	// that way it can be distinguished from an IP address
	return append(bytes.Repeat([]byte{0}, 16), []byte(remoteAddr.String())...)
}
