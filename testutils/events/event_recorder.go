package events

import (
	"reflect"
	"slices"
	"sync"
	"time"

	"github.com/quic-go/quic-go/qlogwriter"
)

// Event is a recorded event with the event time.
type Event struct {
	Time  time.Time
	Event qlogwriter.Event
}

// Trace is a qlog.Trace that returns a qlog recorder.
type Trace struct {
	Recorder qlogwriter.Recorder
}

var _ qlogwriter.Trace = &Trace{}

func (t *Trace) AddProducer() qlogwriter.Recorder {
	return t.Recorder
}

func (t *Trace) SupportsSchemas(string) bool {
	return true
}

// Recorder is a qlog.Recorder that records events.
// Events can be retrieved using the Events method.
type Recorder struct {
	mx     sync.Mutex
	events []Event
}

var _ qlogwriter.Recorder = &Recorder{}

// Events returns all recorded events.
// If filter is provided, only events of the given type(s) are returned.
func (r *Recorder) RecordEvent(ev qlogwriter.Event) {
	r.mx.Lock()
	r.events = append(r.events, Event{Time: time.Now(), Event: ev})
	r.mx.Unlock()
}

// Events returns all recorded events, including the event time.
// If filter is provided, only events of the given type(s) are returned.
func (r *Recorder) Events(filter ...qlogwriter.Event) []qlogwriter.Event {
	eventsWithTime := r.EventsWithTime(filter...)
	events := make([]qlogwriter.Event, 0, len(eventsWithTime))
	for _, ev := range eventsWithTime {
		events = append(events, ev.Event)
	}
	return events
}

func (r *Recorder) EventsWithTime(filter ...qlogwriter.Event) []Event {
	r.mx.Lock()
	events := r.events
	r.mx.Unlock()

	if len(filter) == 0 {
		return events
	}

	// Some events have the same name when serialized, but use different structs.
	// We therefore need to filter by type, and can't use the event name.
	filterTypes := make([]reflect.Type, 0, len(filter))
	for _, f := range filter {
		filterTypes = append(filterTypes, reflect.TypeOf(f))
	}

	var filtered []Event
	for _, ev := range events {
		eventType := reflect.TypeOf(ev.Event)
		if slices.Contains(filterTypes, eventType) {
			filtered = append(filtered, ev)
		}
	}
	return filtered
}

// Clear clears the recorded events.
func (r *Recorder) Clear() {
	r.mx.Lock()
	r.events = nil
	r.mx.Unlock()
}

func (r *Recorder) Close() error { return nil }
