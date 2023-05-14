package ackhandler

import (
	"github.com/quic-go/quic-go/internal/wire"
)

type Frame struct {
	Frame   wire.Frame // nil if the frame has already been acknowledged in another packet
	OnLost  func(wire.Frame)
	OnAcked func(wire.Frame)
}

type StreamFrame struct {
	Frame   *wire.StreamFrame
	Handler interface {
		OnLost(*wire.StreamFrame)
		OnAcked(*wire.StreamFrame)
	}
}
