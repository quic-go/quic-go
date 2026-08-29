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
}

func TestClientSessionCacheRejectsIncompatibleSettings(t *testing.T) {
	stored := &settings{MaxFieldSectionSize: 100, Datagram: true, ExtendedConnect: true}
	underlying := tls.NewLRUClientSessionCache(1)
	session, err := tls.NewResumptionState([]byte("ticket"), &tls.SessionState{
		EarlyData: true,
		Extra:     [][]byte{settingsForSessionTicket(stored)},
	})
	require.NoError(t, err)
	underlying.Put("key", session)
	cache := newClientSessionCache(underlying)
	_, ok := cache.Get("key")
	require.True(t, ok)

	const wantErr = "server sent incompatible settings after accepting 0-RTT"
	for _, tc := range []struct {
		name     string
		settings *settings
	}{
		{name: "lower maximum field section size", settings: &settings{MaxFieldSectionSize: 99, Datagram: true, ExtendedConnect: true}},
		{name: "restore unlimited to limited", settings: &settings{MaxFieldSectionSize: -1, Datagram: true, ExtendedConnect: true}},
		{name: "disable datagrams", settings: &settings{MaxFieldSectionSize: 100, ExtendedConnect: true}},
		{name: "disable extended connect", settings: &settings{MaxFieldSectionSize: 100, Datagram: true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			require.EqualError(t, cache.HandleSettings(tc.settings, true), wantErr)
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
