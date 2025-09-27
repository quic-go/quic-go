package qlog

import (
	"io"
)

type Trace interface {
	AddProducer() Recorder
}

type Recorder interface {
	RecordEvent(Event)
	io.Closer
}
