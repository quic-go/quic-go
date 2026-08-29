package http3

import (
	"bytes"
	"crypto/tls"
	"errors"
	"sync"

	"github.com/quic-go/quic-go/quicvarint"
)

type clientSessionCache struct {
	cache tls.ClientSessionCache

	mutex sync.Mutex

	settingsExtra []byte
	restored      *settings
}

var _ tls.ClientSessionCache = &clientSessionCache{}

func newClientSessionCache(cache tls.ClientSessionCache) *clientSessionCache {
	return &clientSessionCache{cache: cache}
}

func (c *clientSessionCache) Get(key string) (*tls.ClientSessionState, bool) {
	c.mutex.Lock()
	c.restored = nil
	c.mutex.Unlock()

	session, ok := c.cache.Get(key)
	if !ok || session == nil {
		return session, ok
	}
	ticket, state, err := session.ResumptionState()
	if err != nil {
		return nil, false
	}
	if !state.EarlyData {
		return session, true
	}

	if data, ok := settingsDataFromSessionTicket(state.Extra); ok {
		if restored, ok := c.restoreSettings(data); ok {
			c.mutex.Lock()
			c.restored = restored
			c.mutex.Unlock()
			return session, true
		}
	}
	state.EarlyData = false
	session, err = tls.NewResumptionState(ticket, state)
	if err != nil {
		return nil, false
	}
	return session, true
}

func (c *clientSessionCache) Put(key string, session *tls.ClientSessionState) {
	if session == nil {
		c.cache.Put(key, nil)
		return
	}

	c.mutex.Lock()
	extra := c.settingsExtra
	c.mutex.Unlock()
	if extra == nil {
		return
	}

	ticket, state, err := session.ResumptionState()
	if err != nil {
		return
	}
	state.Extra = append(state.Extra, extra)
	session, err = tls.NewResumptionState(ticket, state)
	if err == nil {
		c.cache.Put(key, session)
	}
}

func (c *clientSessionCache) HandleSettings(current *settings, used0RTT bool) error {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	if used0RTT && c.restored != nil {
		old := c.restored
		if old.MaxFieldSectionSize < 0 && current.MaxFieldSectionSize >= 0 ||
			old.MaxFieldSectionSize > current.MaxFieldSectionSize ||
			old.Datagram && !current.Datagram ||
			old.ExtendedConnect && !current.ExtendedConnect {
			return errors.New("server sent incompatible settings after accepting 0-RTT")
		}
	}
	c.settingsExtra = settingsForSessionTicket(current)
	return nil
}

func (*clientSessionCache) restoreSettings(data []byte) (*settings, bool) {
	r := bytes.NewReader(data)
	frameType, err := quicvarint.Read(r)
	if err != nil || frameType != 0x4 {
		return nil, false
	}
	length, err := quicvarint.Read(r)
	if err != nil || uint64(r.Len()) != length {
		return nil, false
	}
	settings, err := parseSettingsFrame(&countingByteReader{Reader: r}, length, 0, nil)
	if err != nil || len(settings.Other) > 0 {
		return nil, false
	}
	return settings, true
}
