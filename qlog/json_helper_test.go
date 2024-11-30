package qlog

import (
	"bytes"
	"encoding/json"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func scaleDuration(t time.Duration) time.Duration {
	scaleFactor := 1
	if f, err := strconv.Atoi(os.Getenv("TIMESCALE_FACTOR")); err == nil { // parsing "" errors, so this works fine if the env is not set
		scaleFactor = f
	}
	if scaleFactor == 0 {
		panic("TIMESCALE_FACTOR must not be 0")
	}
	return time.Duration(scaleFactor) * t
}

func unmarshal(data []byte, v interface{}) error {
	if data[0] == recordSeparator {
		data = data[1:]
	}
	return json.Unmarshal(data, v)
}

func checkEncoding(t *testing.T, data []byte, expected map[string]interface{}) {
	m := make(map[string]interface{})
	require.NoError(t, json.Unmarshal(data, &m))
	require.Len(t, m, len(expected))

	for key, value := range expected {
		switch v := value.(type) {
		case bool, string, map[string]interface{}:
			require.Equal(t, v, m[key])
		case int:
			require.Equal(t, float64(v), m[key])
		case [][]float64: // used in the ACK frame
			require.Contains(t, m, key)
			outerSlice, ok := m[key].([]interface{})
			require.True(t, ok)
			require.Len(t, outerSlice, len(v))
			for i, innerExpected := range v {
				innerSlice, ok := outerSlice[i].([]interface{})
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

type entry struct {
	Time  time.Time
	Name  string
	Event map[string]interface{}
}

func exportAndParse(t *testing.T, buf *bytes.Buffer) []entry {
	m := make(map[string]interface{})
	line, err := buf.ReadBytes('\n')
	require.NoError(t, err)
	require.NoError(t, unmarshal(line, &m))
	require.Contains(t, m, "trace")
	var entries []entry
	trace := m["trace"].(map[string]interface{})
	require.Contains(t, trace, "common_fields")
	commonFields := trace["common_fields"].(map[string]interface{})
	require.Contains(t, commonFields, "reference_time")
	referenceTime := time.Unix(0, int64(commonFields["reference_time"].(float64)*1e6))
	require.NotContains(t, trace, "events")

	for buf.Len() > 0 {
		line, err := buf.ReadBytes('\n')
		require.NoError(t, err)
		ev := make(map[string]interface{})
		require.NoError(t, unmarshal(line, &ev))
		require.Len(t, ev, 3)
		require.Contains(t, ev, "time")
		require.Contains(t, ev, "name")
		require.Contains(t, ev, "data")
		entries = append(entries, entry{
			Time:  referenceTime.Add(time.Duration(ev["time"].(float64)*1e6) * time.Nanosecond),
			Name:  ev["name"].(string),
			Event: ev["data"].(map[string]interface{}),
		})
	}
	return entries
}

func exportAndParseSingle(t *testing.T, buf *bytes.Buffer) entry {
	entries := exportAndParse(t, buf)
	require.Len(t, entries, 1)
	return entries[0]
}
