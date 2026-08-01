package http3

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSettingsCompatibleFor0RTT(t *testing.T) {
	ticket := func(saved *settings) [][]byte {
		return [][]byte{settingsForSessionTicket(saved)}
	}

	for _, tc := range []struct {
		name       string
		current    *settings
		extra      [][]byte
		compatible bool
	}{
		{
			name:       "max field section size increased",
			current:    &settings{MaxFieldSectionSize: 101},
			extra:      ticket(&settings{MaxFieldSectionSize: 100}),
			compatible: true,
		},
		{
			name:    "missing settings",
			current: &settings{},
		},
		{
			name:    "malformed settings",
			current: &settings{},
			extra:   [][]byte{append([]byte(serverSettingsSessionTicketPrefix), 0xff)},
		},
		{
			name:    "max field section size reduced",
			current: &settings{MaxFieldSectionSize: 100},
			extra:   ticket(&settings{MaxFieldSectionSize: 101}),
		},
		{
			name:    "datagrams disabled",
			current: &settings{MaxFieldSectionSize: 100},
			extra: ticket(&settings{
				MaxFieldSectionSize: 100,
				Datagram:            true,
			}),
		},
		{
			name:    "unknown setting",
			current: &settings{MaxFieldSectionSize: 100},
			extra: ticket(&settings{
				MaxFieldSectionSize: 100,
				Other:               map[uint64]uint64{13: 37},
			}),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			data, ok := settingsDataFromSessionTicket(tc.extra)
			require.Equal(t, tc.compatible, ok && settingsCompatibleFor0RTT(data, tc.current))
		})
	}
}
