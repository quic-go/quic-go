package qlog

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	"github.com/francoispqt/gojay"
	"github.com/stretchr/testify/require"
)

type mevent struct{}

var _ eventDetails = mevent{}

func (mevent) Category() category                   { return categoryConnectivity }
func (mevent) Name() string                         { return "mevent" }
func (mevent) IsNil() bool                          { return false }
func (mevent) MarshalJSONObject(enc *gojay.Encoder) { enc.StringKey("event", "details") }

func TestEventMarshaling(t *testing.T) {
	buf := &bytes.Buffer{}
	enc := gojay.NewEncoder(buf)
	err := enc.Encode(event{
		RelativeTime: 1337 * time.Microsecond,
		eventDetails: mevent{},
	})
	require.NoError(t, err)

	var decoded map[string]interface{}
	err = json.Unmarshal(buf.Bytes(), &decoded)
	require.NoError(t, err)
	require.Len(t, decoded, 3)

	require.Equal(t, 1.337, decoded["time"])
	require.Equal(t, "connectivity:mevent", decoded["name"])
	require.Contains(t, decoded, "data")

	data, ok := decoded["data"].(map[string]interface{})
	require.True(t, ok)
	require.Len(t, data, 1)
	require.Equal(t, "details", data["event"])
}
