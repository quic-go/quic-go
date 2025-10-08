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

func newTracer() (Trace, *bytes.Buffer) {
	buf := &bytes.Buffer{}
	trace := NewFileSeq(nopWriteCloser(buf))
	go trace.Run()
	return trace, buf
}

func TestTraceMetadata(t *testing.T) {
	trace, buf := newTracer()
	producer := trace.AddProducer()
	producer.Close()

	var m map[string]any
	require.NoError(t, unmarshal(buf.Bytes(), &m))
	require.Equal(t, "0.3", m["qlog_version"])
	require.Contains(t, m, "title")
	require.Contains(t, m, "trace")
	tr := m["trace"].(map[string]any)
	require.Contains(t, tr, "common_fields")
	commonFields := tr["common_fields"].(map[string]any)
	require.NotContains(t, commonFields, "ODCID")
	require.NotContains(t, commonFields, "group_id")
	require.Contains(t, commonFields, "reference_time")
	referenceTime := time.Unix(0, int64(commonFields["reference_time"].(float64)*1e6))
	require.WithinDuration(t, time.Now(), referenceTime, scaleDuration(10*time.Millisecond))
	require.Equal(t, "relative", commonFields["time_format"])
	require.Contains(t, tr, "vantage_point")
	vantagePoint := tr["vantage_point"].(map[string]any)
	require.Equal(t, "transport", vantagePoint["type"])
}

func newConnectionTracer(t *testing.T) (Recorder, *bytes.Buffer) {
	buf := &bytes.Buffer{}
	trace := NewConnectionFileSeq(
		nopWriteCloser(buf),
		false,
		protocol.ParseConnectionID([]byte{0xde, 0xad, 0xbe, 0xef}),
	)
	go trace.Run()
	recorder := trace.AddProducer()
	t.Cleanup(func() { recorder.Close() })
	return recorder, buf
}

func TestConnectionTraceMetadata(t *testing.T) {
	tracer, buf := newConnectionTracer(t)
	tracer.Close()

	m := make(map[string]any)
	require.NoError(t, unmarshal(buf.Bytes(), &m))
	require.Equal(t, "0.3", m["qlog_version"])
	require.Contains(t, m, "title")
	require.Contains(t, m, "trace")
	trace := m["trace"].(map[string]any)
	require.Contains(t, trace, "common_fields")
	commonFields := trace["common_fields"].(map[string]any)
	require.Equal(t, "deadbeef", commonFields["ODCID"])
	require.Equal(t, "deadbeef", commonFields["group_id"])
	require.Contains(t, commonFields, "reference_time")
	referenceTime := time.Unix(0, int64(commonFields["reference_time"].(float64)*1e6))
	require.WithinDuration(t, time.Now(), referenceTime, scaleDuration(10*time.Millisecond))
	require.Equal(t, "relative", commonFields["time_format"])
	require.Contains(t, trace, "vantage_point")
	vantagePoint := trace["vantage_point"].(map[string]any)
	require.Equal(t, "server", vantagePoint["type"])
}
