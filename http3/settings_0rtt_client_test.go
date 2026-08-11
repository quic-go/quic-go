package http3

import (
	"crypto/tls"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSettingsCompatibleAfter0RTT(t *testing.T) {
	for _, tc := range []struct {
		name       string
		old        *settings
		current    *settings
		compatible bool
	}{
		{
			name:       "unchanged",
			old:        &settings{MaxFieldSectionSize: 100},
			current:    &settings{MaxFieldSectionSize: 100},
			compatible: true,
		},
		{
			name:       "max field section size increased",
			old:        &settings{MaxFieldSectionSize: 100},
			current:    &settings{MaxFieldSectionSize: 101},
			compatible: true,
		},
		{
			name:    "max field section size reduced",
			old:     &settings{MaxFieldSectionSize: 100},
			current: &settings{MaxFieldSectionSize: 99},
		},
		{
			// The default is unlimited, so dropping the value raises the limit,
			// but RFC 9114, section 7.2.4.2 doesn't allow omitting it either.
			name:    "max field section size omitted",
			old:     &settings{MaxFieldSectionSize: 100},
			current: &settings{MaxFieldSectionSize: -1},
		},
		{
			// Going from unlimited to a limit is a reduction as well.
			name:    "max field section size added",
			old:     &settings{MaxFieldSectionSize: -1},
			current: &settings{MaxFieldSectionSize: 100},
		},
		{
			name:       "no max field section size on either side",
			old:        &settings{MaxFieldSectionSize: -1},
			current:    &settings{MaxFieldSectionSize: -1},
			compatible: true,
		},
		{
			name:    "datagrams disabled",
			old:     &settings{MaxFieldSectionSize: -1, Datagram: true},
			current: &settings{MaxFieldSectionSize: -1},
		},
		{
			name:       "datagrams enabled",
			old:        &settings{MaxFieldSectionSize: -1},
			current:    &settings{MaxFieldSectionSize: -1, Datagram: true},
			compatible: true,
		},
		{
			name:    "extended connect disabled",
			old:     &settings{MaxFieldSectionSize: -1, ExtendedConnect: true},
			current: &settings{MaxFieldSectionSize: -1},
		},
		{
			name:       "extended connect enabled",
			old:        &settings{MaxFieldSectionSize: -1},
			current:    &settings{MaxFieldSectionSize: -1, ExtendedConnect: true},
			compatible: true,
		},
		{
			// The omission rule only covers settings that the client understands.
			name:       "unknown setting dropped",
			old:        &settings{MaxFieldSectionSize: -1, Other: map[uint64]uint64{13: 37}},
			current:    &settings{MaxFieldSectionSize: -1},
			compatible: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.compatible, settingsCompatibleAfter0RTT(tc.old, tc.current))
		})
	}
}

// newClientSessionState creates a tls.ClientSessionState carrying the given extra data,
// mimicking what crypto/tls hands to the session cache after a handshake.
func newClientSessionState(t *testing.T, extra [][]byte) *tls.ClientSessionState {
	t.Helper()
	return newClientSessionStateWithEarlyData(t, extra, false)
}

// newClientSessionStateWithEarlyData is like newClientSessionState, but also controls whether
// the ticket may be used for 0-RTT, mimicking a ticket that the server issued with early data
// enabled.
func newClientSessionStateWithEarlyData(t *testing.T, extra [][]byte, earlyData bool) *tls.ClientSessionState {
	t.Helper()

	cs, err := tls.NewResumptionState([]byte("ticket"), &tls.SessionState{Extra: extra, EarlyData: earlyData})
	require.NoError(t, err)
	return cs
}

func earlyDataFromClientSessionState(t *testing.T, cs *tls.ClientSessionState) bool {
	t.Helper()

	_, state, err := cs.ResumptionState()
	require.NoError(t, err)
	return state.EarlyData
}

func extraFromClientSessionState(t *testing.T, cs *tls.ClientSessionState) [][]byte {
	t.Helper()

	_, state, err := cs.ResumptionState()
	require.NoError(t, err)
	return state.Extra
}

// stubClientSessionCache records what was stored, and hands back what it was seeded with.
type stubClientSessionCache struct {
	put  *tls.ClientSessionState
	get  *tls.ClientSessionState
	miss bool
}

var _ tls.ClientSessionCache = &stubClientSessionCache{}

func (c *stubClientSessionCache) Put(_ string, cs *tls.ClientSessionState) { c.put = cs }

func (c *stubClientSessionCache) Get(string) (*tls.ClientSessionState, bool) {
	if c.miss {
		return nil, false
	}
	return c.get, true
}

func TestClientSessionCacheStoresSettings(t *testing.T) {
	current := &settings{MaxFieldSectionSize: 1337, Datagram: true}
	stub := &stubClientSessionCache{}
	zeroRTT := &zeroRTTSettings{}
	zeroRTT.setCurrent(current)
	cache := &clientSessionCache{ClientSessionCache: stub, settings: zeroRTT}

	// quic-go appends its own entry before the session reaches the cache
	cache.Put("key", newClientSessionStateWithEarlyData(t, [][]byte{[]byte("quic-go's entry")}, true))
	require.NotNil(t, stub.put)

	extra := extraFromClientSessionState(t, stub.put)
	require.Len(t, extra, 2)
	require.Equal(t, []byte("quic-go's entry"), extra[0])

	// restoring the settings from that same session yields what we put in, and 0-RTT
	// stays available since there's a baseline to check the server's SETTINGS against
	restoreCache := &clientSessionCache{
		ClientSessionCache: &stubClientSessionCache{get: stub.put},
		settings:           &zeroRTTSettings{},
	}
	cs, ok := restoreCache.Get("key")
	require.True(t, ok)
	require.NotNil(t, cs)
	require.Equal(t, current, restoreCache.settings.getRestored())
	require.True(t, earlyDataFromClientSessionState(t, cs))
}

func TestClientSessionCacheWithoutSettings(t *testing.T) {
	t.Run("settings not received yet", func(t *testing.T) {
		stub := &stubClientSessionCache{}
		cache := &clientSessionCache{ClientSessionCache: stub, settings: &zeroRTTSettings{}}

		// The session ticket can arrive before the server's SETTINGS frame.
		// The session is then stored unmodified, and 0-RTT is not used on the next connection.
		cache.Put("key", newClientSessionState(t, [][]byte{[]byte("quic-go's entry")}))
		require.NotNil(t, stub.put)
		require.Equal(t, [][]byte{[]byte("quic-go's entry")}, extraFromClientSessionState(t, stub.put))
	})

	t.Run("no settings stored", func(t *testing.T) {
		cache := &clientSessionCache{
			ClientSessionCache: &stubClientSessionCache{
				get: newClientSessionStateWithEarlyData(t, [][]byte{[]byte("quic-go's entry")}, true),
			},
			settings: &zeroRTTSettings{},
		}
		cs, ok := cache.Get("key")
		require.True(t, ok)
		require.Nil(t, cache.settings.getRestored())
		// There's nothing to check the server's SETTINGS against, so this ticket must not be
		// used for 0-RTT, even though the server allowed it.
		require.False(t, earlyDataFromClientSessionState(t, cs))
	})

	t.Run("malformed settings", func(t *testing.T) {
		cache := &clientSessionCache{
			ClientSessionCache: &stubClientSessionCache{
				get: newClientSessionStateWithEarlyData(t, [][]byte{
					append([]byte(serverSettingsSessionTicketPrefix), 0xff),
				}, true),
			},
			settings: &zeroRTTSettings{},
		}
		cs, ok := cache.Get("key")
		require.True(t, ok)
		require.Nil(t, cache.settings.getRestored())
		require.False(t, earlyDataFromClientSessionState(t, cs))
	})

	t.Run("no settings stored, ticket not eligible for 0-RTT anyway", func(t *testing.T) {
		cache := &clientSessionCache{
			ClientSessionCache: &stubClientSessionCache{
				get: newClientSessionState(t, [][]byte{[]byte("quic-go's entry")}),
			},
			settings: &zeroRTTSettings{},
		}
		cs, ok := cache.Get("key")
		require.True(t, ok)
		require.Nil(t, cache.settings.getRestored())
		require.False(t, earlyDataFromClientSessionState(t, cs))
	})

	t.Run("cache miss", func(t *testing.T) {
		cache := &clientSessionCache{
			ClientSessionCache: &stubClientSessionCache{miss: true},
			settings:           &zeroRTTSettings{},
		}
		_, ok := cache.Get("key")
		require.False(t, ok)
		require.Nil(t, cache.settings.getRestored())
	})
}
