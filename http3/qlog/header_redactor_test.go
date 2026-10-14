package qlog

import (
	"testing"

	quicqlog "github.com/quic-go/quic-go/qlog"
	"github.com/quic-go/quic-go/qlogwriter"
	"github.com/quic-go/quic-go/testutils/events"

	"github.com/stretchr/testify/require"
)

func TestHeaderRedactor(t *testing.T) {
	var recorder events.Recorder
	trace := NewHeaderRedactor(&events.Trace{Recorder: &recorder}, func(name, value string) string {
		require.Equal(t, "Authorization", name)
		require.Equal(t, "secret", value)
		return "***"
	})
	producer := trace.AddProducer()
	producer.RecordEvent(FrameCreated{Frame: Frame{Frame: HeadersFrame{
		HeaderFields: []HeaderField{{Name: "authorization", Value: "secret"}},
	}}})
	data := FrameParsed{Frame: Frame{Frame: DataFrame{}}}
	mtu := quicqlog.MTUUpdated{Value: 1400}
	producer.RecordEvent(data)
	producer.RecordEvent(mtu)
	require.Equal(t, []qlogwriter.Event{
		FrameCreated{Frame: Frame{Frame: HeadersFrame{HeaderFields: []HeaderField{{Name: "authorization", Value: "***"}}}}},
		data, mtu,
	}, recorder.Events())
	require.NoError(t, producer.Close())
}

func TestHeaderRedactorNil(t *testing.T) {
	redact := func(string, string) string { return "***" }
	require.Nil(t, NewHeaderRedactor(nil, redact))
	trace := &events.Trace{}
	require.Same(t, trace, NewHeaderRedactor(trace, nil))
	require.Nil(t, NewHeaderRedactor(trace, redact).AddProducer())
}
