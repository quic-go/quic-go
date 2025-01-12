package ackhandler

import "github.com/quic-go/quic-go/internal/wire"

// IsFrameAckEliciting returns true if the frame is ack-eliciting.
func IsFrameAckEliciting(f wire.Frame) bool {
	_, isAck := f.(*wire.AckFrame)
	_, isConnectionClose := f.(*wire.ConnectionCloseFrame)
	return !isAck && !isConnectionClose
}

// HasAckElicitingFrames returns true if at least one frame is ack-eliciting.
func HasAckElicitingFrames(fs []Frame) bool {
	for _, f := range fs {
		if IsFrameAckEliciting(f.Frame) {
			return true
		}
	}
	return false
}

// IsProbingFrame returns true if the frame is a probing frame.
func IsProbingFrame(f wire.Frame) bool {
	switch f.(type) {
	case *wire.PathChallengeFrame,
		*wire.PathResponseFrame,
		*wire.NewConnectionIDFrame:
		return true
	}
	return false
}

// HasNonProbingFrames returns true if at least one frame is not a probing frame.
func HasNonProbingFrames(fs []Frame) bool {
	for _, f := range fs {
		if !IsProbingFrame(f.Frame) {
			return true
		}
	}
	return false
}
