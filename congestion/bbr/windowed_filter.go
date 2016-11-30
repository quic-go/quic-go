package bbr

import "github.com/lucas-clemente/quic-go/protocol"

type roundTripCount uint64

type sample struct {
	bandwidth protocol.Bandwidth
	time      roundTripCount
}

// This only implements the maxFilter, for bandwidths

// Implements Kathleen Nichols' algorithm for tracking the minimum (or maximum)
// estimate of a stream of samples over some fixed time interval. (E.g.,
// the minimum RTT over the past five minutes.) The algorithm keeps track of
// the best, second best, and third best min (or max) estimates, maintaining an
// invariant that the measurement time of the n'th best >= n-1'th best.

// The algorithm works as follows. On a reset, all three estimates are set to
// the same sample. The second best estimate is then recorded in the second
// quarter of the window, and a third best estimate is recorded in the second
// half of the window, bounding the worst case error when the true min is
// monotonically increasing (or true max is monotonically decreasing) over the
// window.
//
// A new best sample replaces all three estimates, since the new best is lower
// (or higher) than everything else in the window and it is the most recent.
// The window thus effectively gets reset on every new min. The same property
// holds true for second best and third best estimates. Specifically, when a
// sample arrives that is better than the second best but not better than the
// best, it replaces the second and third best estimates but not the best
// estimate. Similarly, a sample that is better than the third best estimate
// but not the other estimates replaces only the third best estimate.
//
// Finally, when the best expires, it is replaced by the second best, which in
// turn is replaced by the third best. The newest sample replaces the third
// best.

type windowedFilter struct {
	// Time length of window
	windowLength roundTripCount
	// Best estimate is element 0.
	estimates [3]sample

	compare func(a, b protocol.Bandwidth) bool
}

func newWindowedFilter(windowLength roundTripCount) windowedFilter {
	return windowedFilter{
		windowLength: windowLength,
		compare: func(a, b protocol.Bandwidth) bool { // this results in a max filter
			return a >= b
		},
	}
}

// Update updates best estimates with |sample|, and expires and updates best
// estimates as necessary.
func (w *windowedFilter) Update(newBandwidth protocol.Bandwidth, newTime roundTripCount) {
	// Reset all estimates if they have not yet been initialized, if new sample
	// is a new best, or if the newest recorded estimate is too old.
	if w.estimates[0].bandwidth == 0 || w.compare(newBandwidth, w.estimates[0].bandwidth) || newTime-w.estimates[2].time > w.windowLength {
		w.Reset(newBandwidth, newTime)
		return
	}

	newSample := sample{
		bandwidth: newBandwidth,
		time:      newTime,
	}

	if w.compare(newBandwidth, w.estimates[1].bandwidth) {
		w.estimates[1] = newSample
		w.estimates[2] = w.estimates[1]
	} else if w.compare(newBandwidth, w.estimates[2].bandwidth) {
		w.estimates[2] = newSample
	}

	// Expire and update estimates as necessary.
	if newTime-w.estimates[0].time > w.windowLength {
		// The best estimate hasn't been updated for an entire window, so promote
		// second and third best estimates.
		w.estimates[0] = w.estimates[1]
		w.estimates[1] = w.estimates[2]
		w.estimates[2] = newSample
		// Need to iterate one more time. Check if the new best estimate is
		// outside the window as well, since it may also have been recorded a
		// long time ago. Don't need to iterate once more since we cover that
		// case at the beginning of the method.
		if newTime-w.estimates[0].time > w.windowLength {
			w.estimates[0] = w.estimates[1]
			w.estimates[1] = w.estimates[2]
		}
		return
	}

	if w.estimates[1].bandwidth == w.estimates[0].bandwidth && newTime-w.estimates[1].time > (w.windowLength>>2) {
		// A quarter of the window has passed without a better sample, so the
		// second-best estimate is taken from the second quarter of the window.
		w.estimates[2] = newSample
		w.estimates[1] = newSample
		return
	}

	if w.estimates[2].bandwidth == w.estimates[1].bandwidth && newTime-w.estimates[2].time > (w.windowLength>>1) {
		// We've passed a half of the window without a better estimate, so take
		// a third-best estimate from the second half of the window.
		w.estimates[2] = newSample
	}
}

// Reset resets all estimates to new sample.
func (w *windowedFilter) Reset(newBandwidth protocol.Bandwidth, newTime roundTripCount) {
	newSample := sample{bandwidth: newBandwidth, time: newTime}
	w.estimates[0] = newSample
	w.estimates[1] = newSample
	w.estimates[2] = newSample
}

func (w *windowedFilter) GetBest() protocol.Bandwidth {
	return w.estimates[0].bandwidth
}

func (w *windowedFilter) GetSecondBest() protocol.Bandwidth {
	return w.estimates[1].bandwidth
}

func (w *windowedFilter) GetThirdBest() protocol.Bandwidth {
	return w.estimates[2].bandwidth
}
