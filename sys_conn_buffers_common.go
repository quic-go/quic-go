package quic

// largestBufferSize finds the largest socket buffer size in (current, desired)
// that the kernel accepts, and leaves the socket buffer set to it.
// It is called after an attempt to set desired directly didn't take effect.
// Some kernels (e.g. OpenBSD, Darwin) reject requests exceeding their limit
// outright instead of clamping, so without probing the buffer would stay at
// its (much smaller) default size.
// Success is verified by reading the size back, not by the error returned from
// setting it: Linux, for example, silently clamps instead of failing.
func largestBufferSize(current, desired int, set func(int) error, inspect func() (int, error)) (int, error) {
	if desired <= current {
		return current, nil
	}
	known := current // largest size read back after a successful set
	// Invariant: lo took effect (or is the starting size), hi didn't.
	lo, hi := current, desired
	for hi-lo > 1 {
		mid := lo + (hi-lo)/2
		_ = set(mid)
		size, err := inspect()
		if err != nil {
			return known, err
		}
		if size >= mid {
			lo, known = mid, size
		} else {
			hi = mid
		}
	}
	return known, nil
}
