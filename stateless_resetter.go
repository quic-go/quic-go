package quic

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"hash"
	"sync"

	"github.com/lucas-clemente/quic-go/internal/protocol"
)

// statelessResetter handles generation of stateless reset token
type statelessResetter struct {
	enabled bool
	mx      sync.Mutex
	hasher  hash.Hash
}

func newStatelessResetter(key *StatelessResetKey) *statelessResetter {
	r := &statelessResetter{
		enabled: key != nil,
	}
	if r.enabled {
		r.hasher = hmac.New(sha256.New, key[:])
	}
	return r
}

func (r *statelessResetter) Enabled() bool {
	return r.enabled
}

func (r *statelessResetter) GetStatelessResetToken(connID protocol.ConnectionID) protocol.StatelessResetToken {
	var token protocol.StatelessResetToken
	if !r.enabled {
		// Return a random stateless reset token.
		// This token will be sent in the server's transport parameters.
		// By using a random token, an off-path attacker won't be able to disrupt the connection.
		rand.Read(token[:])
		return token
	}
	r.mx.Lock()
	r.hasher.Write(connID.Bytes())
	copy(token[:], r.hasher.Sum(nil))
	r.hasher.Reset()
	r.mx.Unlock()
	return token
}
