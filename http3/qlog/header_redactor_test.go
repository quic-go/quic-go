package qlog

import (
	"context"
	"testing"

	"github.com/quic-go/quic-go"
	quicqlog "github.com/quic-go/quic-go/qlog"
	"github.com/quic-go/quic-go/qlogwriter"
	"github.com/quic-go/quic-go/testutils/events"

	"github.com/stretchr/testify/require"
)

func TestRedactHeaders(t *testing.T) {
	var recorder events.Recorder
	var names []string
	id := quic.ConnectionIDFromBytes([]byte{1, 2, 3})
	tracer := RedactHeaders(func(_ context.Context, client bool, gotID quic.ConnectionID) qlogwriter.Trace {
		require.True(t, client)
		require.Equal(t, id, gotID)
		return &events.Trace{Recorder: &recorder}
	}, func(name, value string) string {
		names = append(names, name)
		require.Equal(t, "secret", value)
		return "***"
	})
	producer := tracer(context.Background(), true, id).AddProducer()
	producer.RecordEvent(FrameCreated{Frame: Frame{Frame: HeadersFrame{
		HeaderFields: []HeaderField{
			{Name: "authorization", Value: "secret"},
			{Name: ":path", Value: "secret"},
		},
	}}})
	data := FrameParsed{Frame: Frame{Frame: DataFrame{}}}
	mtu := quicqlog.MTUUpdated{Value: 1400}
	producer.RecordEvent(data)
	producer.RecordEvent(mtu)
	require.Equal(t, []string{"Authorization", ":path"}, names)
	require.Equal(t, []qlogwriter.Event{
		FrameCreated{Frame: Frame{Frame: HeadersFrame{HeaderFields: []HeaderField{
			{Name: "authorization", Value: "***"},
			{Name: ":path", Value: "***"},
		}}}},
		data, mtu,
	}, recorder.Events())
	require.NoError(t, producer.Close())
}

func TestRedactHeadersNil(t *testing.T) {
	redact := func(string, string) string { return "***" }
	require.Nil(t, RedactHeaders(nil, redact))
	trace := &events.Trace{}
	tracer := func(context.Context, bool, quic.ConnectionID) qlogwriter.Trace { return trace }
	require.Same(t, trace, RedactHeaders(tracer, nil)(context.Background(), true, quic.ConnectionID{}))
	require.Nil(t, RedactHeaders(tracer, redact)(context.Background(), true, quic.ConnectionID{}).AddProducer())
	nilTracer := func(context.Context, bool, quic.ConnectionID) qlogwriter.Trace { return nil }
	require.Nil(t, RedactHeaders(nilTracer, redact)(context.Background(), true, quic.ConnectionID{}))
}
