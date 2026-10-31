package qlog

import (
	"bytes"
	"testing"

	"github.com/quic-go/quic-go/qlogwriter/jsontext"

	"github.com/stretchr/testify/require"
)

func check(t *testing.T, f any, expected string) {
	t.Helper()

	var buf bytes.Buffer
	enc := jsontext.NewEncoder(&buf)
	require.NoError(t, (Frame{Frame: f}).encode(enc, RawInfo{Length: OmitLength, PayloadLength: OmitLength}))
	require.JSONEq(t, expected, buf.String())
}

func TestDataFrame(t *testing.T) {
	check(t, DataFrame{}, `{
		"frame_type": "data"
	}`)
}

func TestHeadersFrame(t *testing.T) {
	check(t, HeadersFrame{}, `{"frame_type":"headers","headers":[]}`)
	check(t, HeadersFrame{
		HeaderFields: []HeaderField{
			{Name: ":status", Value: "200"},
			{Name: "content-type", Value: "application/json"},
			{Name: "x-opaque", Value: "\xff"},
			{Name: "bad name", Value: "ok", InvalidName: true},
			{Name: "x-example", Value: "a\r\nb", InvalidValue: true},
			{Name: "\xff", Value: "ok"},
		},
	}, `{
		"frame_type": "headers",
		"headers": [
			{"name": ":status", "value": "200"},
			{"name": "content-type", "value": "application/json"},
			{"name": "x-opaque", "value_bytes": "ff"},
			{"name_bytes": "626164206e616d65", "value": "ok"},
			{"name": "x-example", "value_bytes": "610d0a62"},
			{"name_bytes": "ff", "value": "ok"}
		]
	}`)
}

func TestGoAwayFrame(t *testing.T) {
	check(t, GoAwayFrame{StreamID: 1337}, `{
		"frame_type": "goaway",
		"id": 1337
	}`)
}

func TestSettingsFrame(t *testing.T) {
	tests := []struct {
		name     string
		frame    SettingsFrame
		expected string
	}{
		{
			name: "datagram: 1",
			frame: SettingsFrame{
				MaxFieldSectionSize: -1,
				Datagram:            new(uint64(1)),
			},
			expected: `{
				"frame_type": "settings",
				"settings": [{
					"name": "settings_h3_datagram",
					"value": 1
				}]
			}`,
		},
		{
			name: "extended_connect: 0",
			frame: SettingsFrame{
				MaxFieldSectionSize: -1,
				ExtendedConnect:     new(uint64(0)),
			},
			expected: `{
				"frame_type": "settings",
				"settings": [{
					"name": "settings_enable_connect_protocol",
					"value": 0
				}]
			}`,
		},
		{
			name:  "max_field_section_size",
			frame: SettingsFrame{MaxFieldSectionSize: 1337},
			expected: `{
				"frame_type": "settings",
				"settings": [{
					"name": "settings_max_field_section_size",
					"value": 1337
				}]
			}`,
		},
		{
			name: "datagram: 0, extended_connect: 0",
			frame: SettingsFrame{
				MaxFieldSectionSize: -1,
				Datagram:            new(uint64(0)),
				ExtendedConnect:     new(uint64(0)),
			},
			expected: `{
				"frame_type": "settings",
				"settings": [
					{"name": "settings_h3_datagram", "value": 0},
					{"name": "settings_enable_connect_protocol", "value": 0}
				]
			}`,
		},
		{
			name: "unknowns",
			// Only test a single unknown setting.
			// Testing multiple unknown settings doesn't add a lot of value,
			// and would require us to deal with non-deterministic map iteration order.
			frame: SettingsFrame{
				MaxFieldSectionSize: -1,
				Other:               map[uint64]uint64{0xdead: 0xbeef},
			},
			expected: `{
				"frame_type": "settings",
				"settings": [{
					"name": "unknown",
					"name_bytes": 57005,
					"value": 48879
				}]
			}`,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			check(t, tc.frame, tc.expected)
		})
	}
}

func TestPushPromiseFrame(t *testing.T) {
	check(t, PushPromiseFrame{}, `{
		"frame_type": "push_promise"
	}`)
}

func TestCancelPushFrame(t *testing.T) {
	check(t, CancelPushFrame{}, `{
		"frame_type": "cancel_push"
	}`)
}

func TestMaxPushIDFrame(t *testing.T) {
	check(t, MaxPushIDFrame{}, `{
		"frame_type": "max_push_id"
	}`)
}

func TestPriorityUpdateFrame(t *testing.T) {
	check(t, PriorityUpdateFrame{StreamID: 12, PriorityFieldValue: "u=1, i"}, `{
		"frame_type": "priority_update",
		"stream_id": 12,
		"priority_field_value": "u=1, i"
	}`)
}

func TestReservedFrame(t *testing.T) {
	check(t, ReservedFrame{Type: 0x1f}, `{
		"frame_type": "reserved",
		"frame_type_bytes": 31
	}`)
}

func TestUnknownFrame(t *testing.T) {
	check(t, UnknownFrame{Type: 0x2a}, `{
		"frame_type": "unknown",
		"frame_type_bytes": 42
	}`)
}
