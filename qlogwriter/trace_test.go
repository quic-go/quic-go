package qlogwriter

import (
	"bytes"
	"encoding/json"
	"io"
	"testing"
	"testing/synctest"
	"time"

	"github.com/quic-go/quic-go/internal/protocol"

	"github.com/stretchr/testify/require"
)

type nopWriteCloserImpl struct{ io.Writer }

func (nopWriteCloserImpl) Close() error { return nil }

func nopWriteCloser(w io.Writer) io.WriteCloser {
	return &nopWriteCloserImpl{Writer: w}
}

func TestTraceMetadata(t *testing.T) {
	t.Run("non-connection trace", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			buf := &bytes.Buffer{}
			trace := NewFileSeq(nopWriteCloser(buf))
			go trace.Run()
			producer := trace.AddProducer()
			producer.Close()

			testTraceMetadata(t, buf, "transport", "", []string{})
		})
	})

	t.Run("connection trace", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			buf := &bytes.Buffer{}
			trace := NewConnectionFileSeq(
				nopWriteCloser(buf),
				false,
				protocol.ParseConnectionID([]byte{0xde, 0xad, 0xbe, 0xef}),
				[]string{"urn:ietf:params:qlog:events:foo", "urn:ietf:params:qlog:events:bar"},
			)

			require.False(t, trace.SupportsSchemas("urn:ietf:params:qlog:events:baz"))
			require.True(t, trace.SupportsSchemas("urn:ietf:params:qlog:events:foo"))
			require.True(t, trace.SupportsSchemas("urn:ietf:params:qlog:events:bar"))

			go trace.Run()
			producer := trace.AddProducer()
			producer.Close()

			testTraceMetadata(t,
				buf,
				"server",
				"deadbeef",
				[]string{"urn:ietf:params:qlog:events:foo", "urn:ietf:params:qlog:events:bar"},
			)
		})
	})
}

func testTraceMetadata(t *testing.T,
	buf *bytes.Buffer,
	expectedVantagePoint,
	expectedGroupID string,
	expectedEventSchemas []string,
) {
	t.Helper()

	data := buf.Bytes()
	require.NotEmpty(t, data)
	require.Equal(t, RecordSeparator, data[0])
	require.Equal(t, byte('\n'), data[len(data)-1])

	commonFields := map[string]any{
		"reference_time": map[string]any{
			"clock_type":      "monotonic",
			"epoch":           "unknown",
			"wall_clock_time": time.Now().Format(time.RFC3339Nano),
		},
	}
	if expectedGroupID != "" {
		commonFields["group_id"] = expectedGroupID
	}
	trace := map[string]any{
		"common_fields": commonFields,
		"vantage_point": map[string]any{
			"type": expectedVantagePoint,
		},
	}
	if len(expectedEventSchemas) > 0 {
		trace["event_schemas"] = expectedEventSchemas
	}
	expected, err := json.Marshal(map[string]any{
		"file_schema":          "urn:ietf:params:qlog:file:sequential",
		"serialization_format": "application/qlog+json-seq",
		"title":                "quic-go qlog",
		"code_version":         quicGoVersion,
		"qlog_format":          "JSON-SEQ",
		"qlog_version":         "0.3",
		"trace":                trace,
	})
	require.NoError(t, err)
	require.JSONEq(t, string(expected), string(data[1:]))
}
