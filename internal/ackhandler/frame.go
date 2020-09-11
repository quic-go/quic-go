package ackhandler

import "github.com/lucas-clemente/quic-go/internal/wire"

type Frame struct {
	wire.Frame
	OnLost  func(*Frame)
	OnAcked func(*Frame)
}
