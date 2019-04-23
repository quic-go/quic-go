package congestion

type WindowedFilter struct {
	length    int64
	estimates []Sample
}

type Sample struct {
	sample int64
	time   int64
}

func NewWindowedFilter(length int64) *WindowedFilter {
	return &WindowedFilter{
		length:    length,
		estimates: make([]Sample, 3),
	}
}

func (f *WindowedFilter) GetBest() int64 {
	return f.estimates[0].sample
}

func (f *WindowedFilter) GetSecondBest() int64 {
	return f.estimates[1].sample
}

func (f *WindowedFilter) GetThirdBest() int64 {
	return f.estimates[2].sample
}

func (f *WindowedFilter) Update(sample int64, time int64) {
	if f.estimates[0].time == 0 || sample > f.estimates[0].sample || (time-f.estimates[2].time) > f.length {
		for i := 0; i < len(f.estimates); i++ {
			f.estimates[i].sample = sample
			f.estimates[i].time = time
		}
		return
	}

	if sample > f.estimates[1].sample {
		f.estimates[1].sample = sample
		f.estimates[1].time = time
		f.estimates[2].sample = sample
		f.estimates[2].time = time
	} else if sample > f.estimates[2].sample {
		f.estimates[2].sample = sample
		f.estimates[2].time = time
	}

	// Expire and update estimates as necessary.
	if time-f.estimates[0].time > f.length {
		// The best estimate hasn't been updated for an entire window, so promote
		// second and third best estimates.
		f.estimates[0].sample = f.estimates[1].sample
		f.estimates[0].time = f.estimates[1].time
		f.estimates[1].sample = f.estimates[2].sample
		f.estimates[1].time = f.estimates[2].time
		f.estimates[2].sample = sample
		f.estimates[2].time = time
		// Need to iterate one more time. Check if the new best estimate is
		// outside the window as well, since it may also have been recorded a
		// long time ago. Don't need to iterate once more since we cover that
		// case at the beginning of the method.
		if time-f.estimates[0].time > f.length {
			f.estimates[0].sample = f.estimates[1].sample
			f.estimates[0].time = f.estimates[1].time
			f.estimates[1].sample = f.estimates[2].sample
			f.estimates[1].time = f.estimates[2].time
		}
		return
	}
	if f.estimates[1].sample == f.estimates[0].sample && time-f.estimates[1].time > f.length>>2 {
		// A quarter of the window has passed without a better sample, so the
		// second-best estimate is taken from the second quarter of the window.
		f.estimates[1].sample = sample
		f.estimates[1].time = time
		f.estimates[2].sample = sample
		f.estimates[2].time = time
		return
	}

	if f.estimates[2].sample == f.estimates[1].sample && time-f.estimates[2].time > f.length>>1 {
		// We've passed a half of the window without a better estimate, so take
		// a third-best estimate from the second half of the window.
		f.estimates[2].sample = sample
		f.estimates[2].time = time
	}
}

func (f *WindowedFilter) Reset(newSample int64, newTime int64) {
	f.estimates[0].sample = newSample
	f.estimates[0].time = newTime
	f.estimates[1].sample = newSample
	f.estimates[1].time = newTime
	f.estimates[2].sample = newSample
	f.estimates[2].time = newTime
}
