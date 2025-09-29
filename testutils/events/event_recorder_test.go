package events

import (
	"testing"

	"github.com/quic-go/quic-go/qlog"
	"github.com/quic-go/quic-go/qlogevents"
	"github.com/stretchr/testify/require"
)

func TestRecorder(t *testing.T) {
	recorder := &Recorder{}
	defer recorder.Close()

	recorder.RecordEvent(qlogevents.MTUUpdated{Value: 1000})
	recorder.RecordEvent(qlogevents.ALPNInformation{ChosenALPN: "foobar"})
	recorder.RecordEvent(qlogevents.ECNStateUpdated{State: qlogevents.ECNStateCapable})
	recorder.RecordEvent(qlogevents.MTUUpdated{Value: 1200})

	require.Equal(t, []qlog.Event{
		qlogevents.MTUUpdated{Value: 1000},
		qlogevents.ALPNInformation{ChosenALPN: "foobar"},
		qlogevents.ECNStateUpdated{State: qlogevents.ECNStateCapable},
		qlogevents.MTUUpdated{Value: 1200},
	}, recorder.Events())

	require.Empty(t, recorder.Events(qlogevents.PacketBuffered{}))
	require.Equal(t, []qlog.Event{
		qlogevents.MTUUpdated{Value: 1000},
		qlogevents.MTUUpdated{Value: 1200},
	}, recorder.Events(qlogevents.MTUUpdated{}))

	recorder.Clear()
	require.Empty(t, recorder.Events())
	require.Empty(t, recorder.Events(qlogevents.MTUUpdated{}))
}
