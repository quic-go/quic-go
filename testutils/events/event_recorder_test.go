package events

import (
	"testing"
	"time"

	"github.com/quic-go/quic-go/internal/synctest"
	"github.com/quic-go/quic-go/qlog"
	"github.com/quic-go/quic-go/qlogwriter"
	"github.com/stretchr/testify/require"
)

func TestRecorder(t *testing.T) {
	recorder := &Recorder{}
	defer recorder.Close()

	recorder.RecordEvent(qlog.MTUUpdated{Value: 1000})
	recorder.RecordEvent(qlog.ALPNInformation{ChosenALPN: "foobar"})
	recorder.RecordEvent(qlog.ECNStateUpdated{State: qlog.ECNStateCapable})
	recorder.RecordEvent(qlog.MTUUpdated{Value: 1200})

	require.Equal(t,
		[]qlogwriter.Event{
			qlog.MTUUpdated{Value: 1000},
			qlog.ALPNInformation{ChosenALPN: "foobar"},
			qlog.ECNStateUpdated{State: qlog.ECNStateCapable},
			qlog.MTUUpdated{Value: 1200},
		},
		recorder.Events(),
	)

	require.Empty(t, recorder.Events(qlog.PacketBuffered{}))
	require.Equal(t,
		[]qlogwriter.Event{
			qlog.MTUUpdated{Value: 1000},
			qlog.MTUUpdated{Value: 1200},
		},
		recorder.Events(qlog.MTUUpdated{}),
	)

	recorder.Clear()
	require.Empty(t, recorder.Events())
	require.Empty(t, recorder.Events(qlog.MTUUpdated{}))
}

func TestRecorderFilterEventsSameName(t *testing.T) {
	// some events have the same name when serialized, but use different structs
	require.Equal(t,
		qlog.PacketReceived{}.Name(),
		qlog.VersionNegotiationReceived{}.Name(),
	)

	recorder := &Recorder{}
	defer recorder.Close()

	recorder.RecordEvent(qlog.PacketReceived{
		Header: qlog.PacketHeader{PacketType: qlog.PacketTypeHandshake},
	})
	recorder.RecordEvent(qlog.VersionNegotiationReceived{
		Header:            qlog.PacketHeaderVersionNegotiation{},
		SupportedVersions: []qlog.Version{0xdeadbeef, 0xdecafbad},
	})

	require.Equal(t,
		[]qlogwriter.Event{
			qlog.PacketReceived{
				Header: qlog.PacketHeader{PacketType: qlog.PacketTypeHandshake},
			},
		},
		recorder.Events(qlog.PacketReceived{}),
	)
	require.Equal(t,
		[]qlogwriter.Event{
			qlog.VersionNegotiationReceived{
				Header:            qlog.PacketHeaderVersionNegotiation{},
				SupportedVersions: []qlog.Version{0xdeadbeef, 0xdecafbad},
			},
		},
		recorder.Events(qlog.VersionNegotiationReceived{}),
	)
}

func TestRecorderEventsWithTime(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		recorder := &Recorder{}
		start := time.Now()
		recorder.RecordEvent(qlog.MTUUpdated{Value: 1000})
		time.Sleep(time.Minute)
		recorder.RecordEvent(qlog.ECNStateUpdated{State: qlog.ECNStateCapable})
		time.Sleep(time.Minute)
		recorder.RecordEvent(qlog.MTUUpdated{Value: 1200})

		require.Equal(t,
			[]Event{
				{Time: start, Event: qlog.MTUUpdated{Value: 1000}},
				{Time: start.Add(2 * time.Minute), Event: qlog.MTUUpdated{Value: 1200}},
			},
			recorder.EventsWithTime(qlog.MTUUpdated{}),
		)
	})
}
