package http3

import (
	"crypto/tls"
	"sync"
)

// zeroRTTSettings carries the server's SETTINGS across a session resumption.
//
// RFC 9114, section 7.2.4.2: when a 0-RTT QUIC connection is being used, the initial value of
// each server setting is the value used in the previous session. Clients therefore store the
// settings the server sent, and check the SETTINGS frame of the resumed connection against them.
type zeroRTTSettings struct {
	mx sync.Mutex
	// restored are the settings recovered from the session ticket.
	// It is nil if no settings were stored alongside the ticket.
	restored *settings
	// current are the settings the server sent on this connection.
	// It is nil until the SETTINGS frame is received.
	current *settings
}

func (s *zeroRTTSettings) setCurrent(sf *settings) {
	s.mx.Lock()
	defer s.mx.Unlock()
	s.current = sf
}

func (s *zeroRTTSettings) getCurrent() *settings {
	s.mx.Lock()
	defer s.mx.Unlock()
	return s.current
}

func (s *zeroRTTSettings) setRestored(sf *settings) {
	s.mx.Lock()
	defer s.mx.Unlock()
	s.restored = sf
}

func (s *zeroRTTSettings) getRestored() *settings {
	s.mx.Lock()
	defer s.mx.Unlock()
	return s.restored
}

// clientSessionCache wraps a tls.ClientSessionCache, storing the server's HTTP/3 SETTINGS
// alongside the session ticket, and restoring them when the session is resumed.
//
// The settings are only ever kept in the client's own session cache. They are not sent to the
// server, and they are not part of the (opaque) session ticket itself.
type clientSessionCache struct {
	tls.ClientSessionCache

	settings *zeroRTTSettings
}

var _ tls.ClientSessionCache = &clientSessionCache{}

func (c *clientSessionCache) Put(key string, cs *tls.ClientSessionState) {
	if cs == nil {
		c.ClientSessionCache.Put(key, nil)
		return
	}
	// The session ticket can be received before the server's SETTINGS frame.
	// RFC 9114, section 7.2.4.2 explicitly allows not storing any settings in that case.
	// The next connection then won't have any settings to rely on, and won't use 0-RTT.
	current := c.settings.getCurrent()
	if current == nil {
		c.ClientSessionCache.Put(key, cs)
		return
	}
	ticket, state, err := cs.ResumptionState()
	if err != nil || state == nil {
		c.ClientSessionCache.Put(key, cs)
		return
	}
	state.Extra = append(state.Extra, settingsForSessionTicket(current))
	newCS, err := tls.NewResumptionState(ticket, state)
	if err != nil {
		c.ClientSessionCache.Put(key, cs)
		return
	}
	c.ClientSessionCache.Put(key, newCS)
}

func (c *clientSessionCache) Get(key string) (*tls.ClientSessionState, bool) {
	cs, ok := c.ClientSessionCache.Get(key)
	if !ok || cs == nil {
		return cs, ok
	}
	ticket, state, err := cs.ResumptionState()
	if err != nil || state == nil {
		return cs, true
	}
	if data, ok := settingsDataFromSessionTicket(state.Extra); ok {
		if sf, err := parseSettingsFromSessionTicket(data); err == nil {
			c.settings.setRestored(sf)
			return cs, true
		}
	}
	// There's no settings baseline stored alongside this ticket, so checkSettingsAfter0RTT has
	// nothing to check the server's SETTINGS against once the connection is established. Strip
	// the ticket of its ability to be used for 0-RTT, rather than silently accepting whatever
	// SETTINGS the server sends.
	if !state.EarlyData {
		return cs, true
	}
	state.EarlyData = false
	newCS, err := tls.NewResumptionState(ticket, state)
	if err != nil {
		return nil, false
	}
	return newCS, true
}
