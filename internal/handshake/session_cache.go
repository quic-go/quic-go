package handshake

import (
	"crypto/tls"

	"github.com/quic-go/quic-go/internal/protocol"
)

// sessionCache stores session tickets separately for each QUIC version.
type sessionCache struct {
	cache   tls.ClientSessionCache
	version protocol.Version
}

var _ tls.ClientSessionCache = &sessionCache{}

func newSessionCache(cache tls.ClientSessionCache, v protocol.Version) *sessionCache {
	return &sessionCache{cache: cache, version: v}
}

func (c *sessionCache) Get(key string) (*tls.ClientSessionState, bool) {
	return c.cache.Get(protocol.VersionedKey(key, c.version))
}

func (c *sessionCache) Put(key string, cs *tls.ClientSessionState) {
	c.cache.Put(protocol.VersionedKey(key, c.version), cs)
}
