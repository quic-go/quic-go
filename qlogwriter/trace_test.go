package qlogwriter

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/quic-go/quic-go/internal/protocol"

	"github.com/stretchr/testify/require"
)

type nopWriteCloserImpl struct{ io.Writer }

func (nopWriteCloserImpl) Close() error { return nil }

func nopWriteCloser(w io.Writer) io.WriteCloser {
	return &nopWriteCloserImpl{Writer: w}
}

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

func unmarshal(data []byte, v any) error {
	if bytes.Equal(data[:1], recordSeparator) {
		data = data[1:]
	}
	return json.Unmarshal(data, v)
}

func TestTraceMetadata(t *testing.T) {
	t.Run("non-connection trace", func(t *testing.T) {
		buf := &bytes.Buffer{}
		trace := NewFileSeq(nopWriteCloser(buf))
		go trace.Run()
		producer := trace.AddProducer()
		producer.Close()

		testTraceMetadata(t, buf, "transport", "")
	})

	t.Run("connection trace", func(t *testing.T) {
		buf := &bytes.Buffer{}
		trace := NewConnectionFileSeq(
			nopWriteCloser(buf),
			false,
			protocol.ParseConnectionID([]byte{0xde, 0xad, 0xbe, 0xef}),
		)
		go trace.Run()
		producer := trace.AddProducer()
		producer.Close()

		testTraceMetadata(t, buf, "server", "deadbeef")
	})
}

func testTraceMetadata(t *testing.T, buf *bytes.Buffer, expectedVantagePoint, expectedGroupID string) {
	var m map[string]any
	require.NoError(t, unmarshal(buf.Bytes(), &m))
	require.Equal(t, "0.3", m["qlog_version"])
	require.Contains(t, m, "title")
	require.Contains(t, m, "trace")
	tr := m["trace"].(map[string]any)
	require.Contains(t, tr, "common_fields")
	commonFields := tr["common_fields"].(map[string]any)
	if expectedGroupID != "" {
		require.Contains(t, commonFields, "group_id")
		require.Equal(t, expectedGroupID, commonFields["group_id"])
	} else {
		require.NotContains(t, commonFields, "group_id")
	}
	require.Contains(t, commonFields, "reference_time")
	referenceTimeMap := commonFields["reference_time"].(map[string]any)
	require.Contains(t, referenceTimeMap, "clock_type")
	require.Equal(t, "monotonic", referenceTimeMap["clock_type"])
	require.Contains(t, referenceTimeMap, "epoch")
	require.Equal(t, "unknown", referenceTimeMap["epoch"])
	require.Contains(t, referenceTimeMap, "wall_clock_time")
	wallClockTimeStr := referenceTimeMap["wall_clock_time"].(string)
	wallClockTime, err := time.Parse(time.RFC3339Nano, wallClockTimeStr)
	require.NoError(t, err)
	require.WithinDuration(t, time.Now(), wallClockTime, scaleDuration(10*time.Millisecond))
	require.Contains(t, tr, "vantage_point")
	vantagePoint := tr["vantage_point"].(map[string]any)
	require.Equal(t, expectedVantagePoint, vantagePoint["type"])
}
