package wire

// IsProbingFrame returns true if the frame is a probing frame.
// See section 9.1 of RFC 9000.
func IsProbingFrame(f Frame) bool {
	switch f.(type) {
	case *PathChallengeFrame, *PathResponseFrame, *NewConnectionIDFrame:
		return true
	}
	return false
}
