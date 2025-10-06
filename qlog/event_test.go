package qlog

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	"github.com/quic-go/quic-go/qlog/jsontext"

	"github.com/stretchr/testify/require"
)

type mevent struct{}

var _ eventDetails = mevent{}

func (mevent) Name() string { return "foobar:mevent" }
func (mevent) Encode(enc *jsontext.Encoder) error {
	if err := enc.WriteToken(jsontext.BeginObject); err != nil {
		return err
	}
	if err := enc.WriteToken(jsontext.String("event")); err != nil {
		return err
	}
	if err := enc.WriteToken(jsontext.String("details")); err != nil {
		return err
	}
	return enc.WriteToken(jsontext.EndObject)
}

func TestEventMarshaling(t *testing.T) {
	buf := &bytes.Buffer{}
	enc := jsontext.NewEncoder(buf)
	err := (event{
		RelativeTime: 1337 * time.Microsecond,
		eventDetails: mevent{},
	}).Encode(enc)
	require.NoError(t, err)

	var decoded map[string]any
	err = json.Unmarshal(buf.Bytes(), &decoded)
	require.NoError(t, err)
	require.Len(t, decoded, 3)

	require.Equal(t, 1.337, decoded["time"])
	require.Equal(t, "foobar:mevent", decoded["name"])
	require.Contains(t, decoded, "data")

	data, ok := decoded["data"].(map[string]any)
	require.True(t, ok)
	require.Len(t, data, 1)
	require.Equal(t, "details", data["event"])
}
