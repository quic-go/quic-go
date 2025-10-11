package qlog

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/quic-go/quic-go/qlogwriter/jsontext"

	"github.com/stretchr/testify/require"
)

func check(t *testing.T, f any, expected map[string]any) {
	var buf bytes.Buffer
	enc := jsontext.NewEncoder(&buf)
	require.NoError(t, (Frame{Frame: f}).encode(enc))
	data := buf.Bytes()
	require.True(t, json.Valid(data), "invalid JSON: %s", string(data))
	checkEncoding(t, data, expected)
}

func checkEncoding(t *testing.T, data []byte, expected map[string]any) {
	t.Helper()

	m := make(map[string]any)
	require.NoError(t, json.Unmarshal(data, &m))
	require.Len(t, m, len(expected))

	for key, value := range expected {
		switch v := value.(type) {
		case bool, string, map[string]any:
			require.Equal(t, v, m[key])
		case int:
			require.Equal(t, float64(v), m[key])
		case float64:
			require.Equal(t, v, m[key])
		case []map[string]any: // used for header fields
			require.Contains(t, m, key)
			slice, ok := m[key].([]any)
			require.True(t, ok)
			require.Len(t, slice, len(v))
			for i, expectedField := range v {
				field, ok := slice[i].(map[string]any)
				require.True(t, ok)
				require.Equal(t, expectedField, field)
			}
		default:
			t.Fatalf("unexpected type: %T", v)
		}
	}
}

func TestDataFrame(t *testing.T) {
	check(t, DataFrame{}, map[string]any{
		"frame_type": "data",
	})
}

func TestHeadersFrame(t *testing.T) {
	check(t, HeadersFrame{
		HeaderFields: []HeaderField{
			{Name: ":status", Value: "200"},
			{Name: "content-type", Value: "application/json"},
		},
	}, map[string]any{
		"frame_type": "headers",
		"header_fields": []map[string]any{
			{"name": ":status", "value": "200"},
			{"name": "content-type", "value": "application/json"},
		},
	})
}

func TestGoAwayFrame(t *testing.T) {
	check(t, GoAwayFrame{StreamID: 1337}, map[string]any{
		"frame_type": "goaway",
		"id":         1337,
	})
}
