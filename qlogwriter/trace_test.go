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
		resetEventSchemas(t)
		RegisterEventSchema("urn:ietf:params:qlog:events:foo")

		synctest.Test(t, func(t *testing.T) {
			buf := &bytes.Buffer{}
			trace := NewFileSeq(nopWriteCloser(buf))
			go trace.Run()
			producer := trace.AddProducer()
			producer.Close()

			testTraceMetadata(t, buf, "transport", "", []string{"urn:ietf:params:qlog:events:foo"})
		})
	})

	t.Run("connection trace", func(t *testing.T) {
		resetEventSchemas(t)
		RegisterEventSchema("urn:ietf:params:qlog:events:foo")
		RegisterEventSchema("urn:ietf:params:qlog:events:bar")

		synctest.Test(t, func(t *testing.T) {
			buf := &bytes.Buffer{}
			trace := NewConnectionFileSeq(
				nopWriteCloser(buf),
				false,
				protocol.ParseConnectionID([]byte{0xde, 0xad, 0xbe, 0xef}),
			)

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

	// file_schema and serialization_format SHOULD be in the first 256 bytes,
	// see https://www.ietf.org/archive/id/draft-ietf-quic-qlog-main-schema-15.html#section-3
	dec := json.NewDecoder(bytes.NewReader(data[1:256]))
	_, err := dec.Token() // opening brace
	require.NoError(t, err)
	fields := make(map[string]any)
	for { // decoding fails at the field cut off at byte 256
		key, err := dec.Token()
		if err != nil {
			break
		}
		var val any
		if err := dec.Decode(&val); err != nil {
			break
		}
		fields[key.(string)] = val
	}
	require.Equal(t, "urn:ietf:params:qlog:file:sequential", fields["file_schema"])
	require.Equal(t, "application/qlog+json-seq", fields["serialization_format"])

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
		"implementation": map[string]any{
			"name":    "quic-go",
			"version": quicGoVersion,
		},
	}
	if len(expectedEventSchemas) > 0 {
		trace["event_schemas"] = expectedEventSchemas
	}
	expected, err := json.Marshal(map[string]any{
		"file_schema":          "urn:ietf:params:qlog:file:sequential",
		"serialization_format": "application/qlog+json-seq",
		"title":                "quic-go qlog",
		"qlog_format":          "JSON-SEQ",
		"qlog_version":         "0.3",
		"trace":                trace,
	})
	require.NoError(t, err)
	require.JSONEq(t, string(expected), string(data[1:]))
}
