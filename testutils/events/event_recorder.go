package events

import (
	"fmt"
	"slices"
	"sync"

	"github.com/quic-go/quic-go/qlog"
)

type Recorder struct {
	mx     sync.Mutex
	events []qlog.Event
}

var _ qlog.Recorder = &Recorder{}

func (r *Recorder) RecordEvent(ev qlog.Event) {
	r.mx.Lock()
	r.events = append(r.events, ev)
	r.mx.Unlock()
}

func (r *Recorder) Events(filter ...qlog.Event) []qlog.Event {
	r.mx.Lock()
	events := r.events
	r.mx.Unlock()

	if len(filter) == 0 {
		return events
	}

	names := make([]string, 0, len(filter))
	for _, f := range filter {
		names = append(names, f.Name())
	}

	var filtered []qlog.Event
	for _, event := range events {
		fmt.Println(event.Name())
		if slices.Contains(names, event.Name()) {
			filtered = append(filtered, event)
		}
	}
	return filtered
}

func (r *Recorder) Clear() {
	r.mx.Lock()
	r.events = nil
	r.mx.Unlock()
}

func (r *Recorder) Close() error { return nil }
