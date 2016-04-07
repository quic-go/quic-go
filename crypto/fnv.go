package crypto

// Taken and modified from https://golang.org/src/hash/fnv/fnv.go
// TODO: This implementation uses big ints and is probably horrendously slow.

// Implements FNV-1 and FNV-1a, non-cryptographic hash functions
// created by Glenn Fowler, Landon Curt Noll, and Phong Vo.
// See https://en.wikipedia.org/wiki/Fowler-Noll-Vo_hash_function.

import (
	"hash"
	"math/big"
)

// Hash128 is the common interface implemented by all 128-bit hash functions.
type Hash128 interface {
	hash.Hash
	Sum128() []byte
}

type sum128a struct {
	*big.Int
}

var _ Hash128 = &sum128a{}

var offset128 = &big.Int{}
var prime128 = &big.Int{}

func init() {
	offset128.SetString("144066263297769815596495629667062367629", 0)
	prime128.SetString("309485009821345068724781371", 0)
}

// New128a returns a new 128-bit FNV-1a hash.Hash.
func New128a() Hash128 {
	i := &big.Int{}
	i.Set(offset128)
	return &sum128a{i}
}

func (s *sum128a) Reset() { s.Set(offset128) }

func (s *sum128a) Sum128() []byte { return s.Bytes() }

func (s *sum128a) Write(data []byte) (int, error) {
	for _, c := range data {
		s.Xor(s.Int, big.NewInt(int64(c)))
		s.Mul(s.Int, prime128)

		// Truncate the bigint to 128 bits
		s.SetBytes(s.Bytes()[len(s.Bytes())-16 : len(s.Bytes())])
	}
	return len(data), nil
}

func (s *sum128a) Size() int { return 16 }

func (s *sum128a) BlockSize() int { return 1 }

func (s *sum128a) Sum(in []byte) []byte {
	b := s.Bytes()
	return append(in, b[len(b)-s.Size():]...)
}
