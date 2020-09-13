package ackhandler

import "github.com/lucas-clemente/quic-go/internal/wire"

type Frame struct {
	wire.Frame // might be nil once the frame has been retransmitted

	OnLost  func(*Frame)
	OnAcked func(*Frame)

	retransmittedAs []*Frame
}

func (f *Frame) onAcked() {
	for _, r := range f.retransmittedAs {
		r.onAcked()
	}
	if f.Frame != nil && f.OnAcked != nil {
		f.OnAcked(f)
	}
}

func (f *Frame) RetransmittedAs(r *Frame) {
	f.retransmittedAs = append(f.retransmittedAs, r)
}
