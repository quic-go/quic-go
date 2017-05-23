package handshake

import (
	"net"
	"time"

	"github.com/lucas-clemente/quic-go/crypto"
)

const (
	stkPrefixIP byte = iota
	stkPrefixString
)

// An STK is a source address token
type STK struct {
	RemoteAddr string
	SentTime   time.Time
}

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

// DecodeToken decodes an STK token
func (g *STKGenerator) DecodeToken(data []byte) (*STK, error) {
	// if the client didn't send any STK, DecodeToken will be called with a nil-slice
	if len(data) == 0 {
		return nil, nil
	}
	remote, timestamp, err := g.stkSource.DecodeToken(data)
	if err != nil {
		return nil, err
	}
	return &STK{
		RemoteAddr: decodeRemoteAddr(remote),
		SentTime:   timestamp,
	}, nil
}

// encodeRemoteAddr encodes a remote address such that it can be saved in the STK
func encodeRemoteAddr(remoteAddr net.Addr) []byte {
	if udpAddr, ok := remoteAddr.(*net.UDPAddr); ok {
		return append([]byte{stkPrefixIP}, udpAddr.IP...)
	}
	return append([]byte{stkPrefixString}, []byte(remoteAddr.String())...)
}

// decodeRemoteAddr decodes the remote address saved in the STK
func decodeRemoteAddr(data []byte) string {
	if data[0] == stkPrefixIP {
		return net.IP(data[1:]).String()
	}
	return string(data[1:])
}
