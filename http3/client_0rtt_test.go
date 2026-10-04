package http3

import (
	"crypto/tls"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestClientSessionCacheStoresAndRestoresSettings(t *testing.T) {
	underlying := tls.NewLRUClientSessionCache(1)
	cache := newClientSessionCache(underlying)
	session, err := tls.NewResumptionState([]byte("ticket"), &tls.SessionState{EarlyData: true})
	require.NoError(t, err)

	cache.Put("key", session)
	_, ok := underlying.Get("key")
	require.False(t, ok)

	want := &settings{MaxFieldSectionSize: 100, Datagram: true, ExtendedConnect: true}
	require.NoError(t, cache.HandleSettings(want, false))
	_, ok = underlying.Get("key")
	require.False(t, ok)

	cache.Put("key", session)
	restoring := newClientSessionCache(underlying)
	session, ok = restoring.Get("key")
	require.True(t, ok)
	_, state, err := session.ResumptionState()
	require.NoError(t, err)
	require.True(t, state.EarlyData)
	require.NoError(t, restoring.HandleSettings(want, true))
	// Omitting MAX_FIELD_SECTION_SIZE restores its unlimited default and is compatible.
	require.NoError(t, restoring.HandleSettings(&settings{MaxFieldSectionSize: -1, Datagram: true, ExtendedConnect: true}, true))
}

func TestClientSessionCacheRejectsIncompatibleSettings(t *testing.T) {
	underlying := tls.NewLRUClientSessionCache(1)
	cache := newClientSessionCache(underlying)

	const wantErr = "server sent incompatible settings after accepting 0-RTT"
	limited := &settings{MaxFieldSectionSize: 100, Datagram: true, ExtendedConnect: true}
	unlimited := &settings{MaxFieldSectionSize: -1, Datagram: true, ExtendedConnect: true}

	for _, tc := range []struct {
		name            string
		stored, current *settings
	}{
		{
			name:    "lower maximum field section size",
			stored:  limited,
			current: &settings{MaxFieldSectionSize: 99, Datagram: true, ExtendedConnect: true},
		},
		{
			name:    "restore unlimited to limited",
			stored:  unlimited,
			current: limited,
		},
		{
			name:    "disable datagrams",
			stored:  limited,
			current: &settings{MaxFieldSectionSize: 100, ExtendedConnect: true},
		},
		{
			name:    "disable extended connect",
			stored:  limited,
			current: &settings{MaxFieldSectionSize: 100, Datagram: true},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			session, err := tls.NewResumptionState([]byte("ticket"), &tls.SessionState{
				EarlyData: true,
				Extra:     [][]byte{settingsForSessionTicket(tc.stored)},
			})
			require.NoError(t, err)
			underlying.Put("key", session)
			_, ok := cache.Get("key")
			require.True(t, ok)
			require.EqualError(t, cache.HandleSettings(tc.current, true), wantErr)
		})
	}
}

func TestClientSessionCacheDisables0RTTWithoutRestorableSettings(t *testing.T) {
	for _, tc := range []struct {
		name  string
		extra [][]byte
	}{
		{name: "missing"},
		{name: "malformed", extra: [][]byte{append([]byte(settingsSessionTicketPrefix), 0xff)}},
		{name: "unknown", extra: [][]byte{settingsForSessionTicket(&settings{Other: map[uint64]uint64{13: 37}})}},
	} {
		underlying := tls.NewLRUClientSessionCache(1)
		session, err := tls.NewResumptionState(
			[]byte("ticket"),
			&tls.SessionState{EarlyData: true, Extra: tc.extra},
		)
		require.NoError(t, err, tc.name)
		underlying.Put("key", session)

		cache := newClientSessionCache(underlying)
		session, ok := cache.Get("key")
		require.True(t, ok, tc.name)
		_, state, err := session.ResumptionState()
		require.NoError(t, err, tc.name)
		require.False(t, state.EarlyData, tc.name)
	}
}
