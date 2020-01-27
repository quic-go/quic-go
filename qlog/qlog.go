package qlog

import (
	"io"
	"time"

	"github.com/lucas-clemente/quic-go/internal/congestion"

	"github.com/francoispqt/gojay"
	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/wire"
)

// A Tracer records events to be exported to a qlog.
type Tracer interface {
	Export() error
	SentPacket(time.Time, *wire.ExtendedHeader, *wire.AckFrame, []wire.Frame)
	ReceivedRetry(time.Time, *wire.Header)
	ReceivedPacket(time.Time, *wire.ExtendedHeader, []wire.Frame)
	UpdatedMetrics(time time.Time, rttStats *congestion.RTTStats, cwnd protocol.ByteCount, bytesInFLight protocol.ByteCount, packetsInFlight int)
	LostPacket(time.Time, protocol.EncryptionLevel, protocol.PacketNumber, PacketLossReason)
}

type tracer struct {
	w           io.WriteCloser
	odcid       protocol.ConnectionID
	perspective protocol.Perspective

	events []event
}

var _ Tracer = &tracer{}

// NewTracer creates a new tracer to record a qlog.
func NewTracer(w io.WriteCloser, p protocol.Perspective, odcid protocol.ConnectionID) Tracer {
	return &tracer{
		w:           w,
		perspective: p,
		odcid:       odcid,
	}
}

func (t *tracer) Active() bool { return true }

// Export writes a qlog.
func (t *tracer) Export() error {
	enc := gojay.NewEncoder(t.w)
	tl := &topLevel{
		traces: traces{
			{
				VantagePoint: vantagePoint{Type: t.perspective},
				CommonFields: commonFields{ODCID: connectionID(t.odcid), GroupID: connectionID(t.odcid)},
				EventFields:  eventFields[:],
				Events:       t.events,
			},
		}}
	if err := enc.Encode(tl); err != nil {
		return err
	}
	return t.w.Close()
}

func (t *tracer) SentPacket(time time.Time, hdr *wire.ExtendedHeader, ack *wire.AckFrame, frames []wire.Frame) {
	numFrames := len(frames)
	if ack != nil {
		numFrames++
	}
	fs := make([]frame, 0, numFrames)
	if ack != nil {
		fs = append(fs, *transformFrame(ack))
	}
	for _, f := range frames {
		fs = append(fs, *transformFrame(f))
	}
	t.events = append(t.events, event{
		Time: time,
		eventDetails: eventPacketSent{
			PacketType: getPacketTypeFromHeader(hdr),
			Header:     *transformExtendedHeader(hdr),
			Frames:     fs,
		},
	})
}

func (t *tracer) ReceivedPacket(time time.Time, hdr *wire.ExtendedHeader, frames []wire.Frame) {
	fs := make([]frame, len(frames))
	for i, f := range frames {
		fs[i] = *transformFrame(f)
	}
	t.events = append(t.events, event{
		Time: time,
		eventDetails: eventPacketReceived{
			PacketType: getPacketTypeFromHeader(hdr),
			Header:     *transformExtendedHeader(hdr),
			Frames:     fs,
		},
	})
}

func (t *tracer) ReceivedRetry(time time.Time, hdr *wire.Header) {
	t.events = append(t.events, event{
		Time: time,
		eventDetails: eventRetryReceived{
			Header: *transformHeader(hdr),
		},
	})
}

func (t *tracer) UpdatedMetrics(time time.Time, rttStats *congestion.RTTStats, cwnd, bytesInFlight protocol.ByteCount, packetsInFlight int) {
	t.events = append(t.events, event{
		Time: time,
		eventDetails: eventMetricsUpdated{
			MinRTT:           rttStats.MinRTT(),
			SmoothedRTT:      rttStats.SmoothedRTT(),
			LatestRTT:        rttStats.LatestRTT(),
			RTTVariance:      rttStats.MeanDeviation(),
			CongestionWindow: cwnd,
			BytesInFlight:    bytesInFlight,
			PacketsInFlight:  packetsInFlight,
		},
	})
}

func (t *tracer) LostPacket(time time.Time, encLevel protocol.EncryptionLevel, pn protocol.PacketNumber, lossReason PacketLossReason) {
	t.events = append(t.events, event{
		Time: time,
		eventDetails: eventPacketLost{
			PacketType:   getPacketTypeFromEncryptionLevel(encLevel),
			PacketNumber: pn,
			Trigger:      lossReason,
		},
	})
}
