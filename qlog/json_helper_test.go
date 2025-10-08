package qlog

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

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
		case [][]float64: // used in the ACK frame
			require.Contains(t, m, key)
			outerSlice, ok := m[key].([]any)
			require.True(t, ok)
			require.Len(t, outerSlice, len(v))
			for i, innerExpected := range v {
				innerSlice, ok := outerSlice[i].([]any)
				require.True(t, ok)
				require.Len(t, innerSlice, len(innerExpected))
				for j, expectedValue := range innerExpected {
					v, ok := innerSlice[j].(float64)
					require.True(t, ok)
					require.Equal(t, expectedValue, v)
				}
			}
		default:
			t.Fatalf("unexpected type: %T", v)
		}
	}
}
