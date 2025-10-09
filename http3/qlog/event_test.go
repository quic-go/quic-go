package qlog

import (
	"bytes"
	"encoding/json"
	"io"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/internal/synctest"
	"github.com/quic-go/quic-go/qlogwriter"

	"github.com/stretchr/testify/require"
)

type nopWriteCloserImpl struct{ io.Writer }

func (nopWriteCloserImpl) Close() error { return nil }

func nopWriteCloser(w io.Writer) io.WriteCloser {
	return &nopWriteCloserImpl{Writer: w}
}

func testEventEncoding(t *testing.T, ev qlogwriter.Event) (string, map[string]any) {
	t.Helper()
	var buf bytes.Buffer

	synctest.Test(t, func(t *testing.T) {
		tr := qlogwriter.NewConnectionFileSeq(
			nopWriteCloser(&buf),
			true,
			quic.ConnectionIDFromBytes([]byte{1, 2, 3, 4}),
			[]string{"http3"},
		)
		go tr.Run()
		producer := tr.AddProducer()

		synctest.Wait()
		time.Sleep(42 * time.Second)

		producer.RecordEvent(ev)
		producer.Close()
	})

	return decode(t, buf.String())
}

func decode(t *testing.T, data string) (string, map[string]any) {
	t.Helper()

	var result map[string]any

	lines := bytes.Split([]byte(data), []byte{'\n'})
	require.Len(t, lines, 3) // the first line is the trace header, the second line is the event, the third line is empty
	require.Empty(t, lines[2])
	require.Equal(t, qlogwriter.RecordSeparator, lines[1][0], "expected record separator at start of line")
	require.NoError(t, json.Unmarshal(lines[1][1:], &result))
	require.Equal(t, 42*time.Second, time.Duration(result["time"].(float64)*1e6)*time.Nanosecond)

	return result["name"].(string), result["data"].(map[string]any)
}

func TestFrameParsedEvent(t *testing.T) {
	name, ev := testEventEncoding(t, FrameParsed{
		StreamID: quic.StreamID(4),
		Raw: RawInfo{
			Length:        1500,
			PayloadLength: 100,
		},
		Frame: Frame{Frame: &DataFrame{}},
	})

	require.Equal(t, "http3:frame_parsed", name)
	require.Equal(t, float64(4), ev["stream_id"])
	require.Equal(t, "frame_parsed", ev["name"])
	require.Contains(t, ev, "frame")
}

func TestFrameCreatedEvent(t *testing.T) {
	name, ev := testEventEncoding(t, FrameCreated{
		StreamID: quic.StreamID(8),
		Raw: RawInfo{
			PayloadLength: 200,
		},
		Frame: Frame{Frame: &HeadersFrame{
			HeaderFields: []HeaderField{
				{Name: ":status", Value: "200"},
				{Name: "content-type", Value: "text/html"},
			},
		}},
	})

	require.Equal(t, "http3:frame_created", name)
	require.Equal(t, float64(8), ev["stream_id"])
	require.Equal(t, "frame_created", ev["name"])
	require.Contains(t, ev, "frame")
}
