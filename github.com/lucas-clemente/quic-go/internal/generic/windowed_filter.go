package generic

type Type uint64
type TypeTime uint64
type TypeTimeDelta uint64
type TypeCompare func(Type, Type)bool

type TypeSample struct {
	sample Type
 	time   TypeTime
}

func NewTypeSample(sample Type, time TypeTime) *TypeSample {
	return &TypeSample{sample: sample, time: time}
}


type TypeWindowedFilter struct {
	windowLength TypeTimeDelta // Time length of window.
	zeroValue    Type          // Uninitialized value of Type.
	estimates    [3]TypeSample // Best estimate is element 0.
	compare      TypeCompare
}



// |window_length| is the period after which a best estimate expires.
// |zero_value| is used as the uninitialized value for objects of Type.
// Importantly, |zero_value| should be an invalid value for a true sample.
func NewWindowedFilter(window_length_ TypeTimeDelta, zero_value_ Type, estimates_ [3]TypeSample) *TypeWindowedFilter {
	return &TypeWindowedFilter{windowLength: window_length_, zeroValue: zero_value_, estimates: estimates_}
}



// Changes the window length.  Does not update any current samples.
func (w *TypeWindowedFilter) SetWindow_length_(window_length_ TypeTimeDelta) {
	w.windowLength = window_length_
}

// Updates best estimates with |sample|, and expires and updates best
// estimates as necessary.
func (w *TypeWindowedFilter) Update(newSample Type, newTime TypeTime) {
	// Reset all estimates if they have not yet been initialized, if new sample
	// is a new best, or if the newest recorded estimate is too old.
	if w.estimates[0].sample == w.zeroValue ||
		w.compare(newSample, w.estimates[0].sample) ||
		TypeTimeDelta(newTime- w.estimates[2].time) > w.windowLength {
		w.Reset(newSample, newTime)
		return
	}

	if w.compare(newSample, w.estimates[1].sample) {
		w.estimates[1] = *NewTypeSample(newSample, newTime)
		w.estimates[2] = w.estimates[1]
	} else if w.compare(newSample, w.estimates[2].sample) {
		w.estimates[2] = *NewTypeSample(newSample, newTime)
	}

	// Expire and update estimates as necessary.
	if TypeTimeDelta(newTime- w.estimates[0].time) > w.windowLength {
		// The best estimate hasn't been updated for an entire window, so promote
		// second and third best estimates.
		w.estimates[0] = w.estimates[1]
		w.estimates[1] = w.estimates[2]
		w.estimates[2] = *NewTypeSample(newSample, newTime)
		// Need to iterate one more time. Check if the new best estimate is
		// outside the window as well, since it may also have been recorded a
		// long time ago. Don't need to iterate once more since we cover that
		// case at the beginning of the method.
		if TypeTimeDelta(newTime- w.estimates[0].time) > w.windowLength {
			w.estimates[0] = w.estimates[1]
			w.estimates[1] = w.estimates[2]
		}
		return;
	}
	if w.estimates[1].sample == w.estimates[0].sample &&
		TypeTimeDelta(newTime- w.estimates[1].time) > w.windowLength>> 2 {
		// A quarter of the window has passed without a better sample, so the
		// second-best estimate is taken from the second quarter of the window.
		w.estimates[2] = *NewTypeSample(newSample, newTime)
		w.estimates[1] = w.estimates[2]
		return
	}

	if w.estimates[2].sample == w.estimates[1].sample &&
		TypeTimeDelta(newTime- w.estimates[2].time) > w.windowLength>> 1 {
		// We've passed a half of the window without a better estimate, so take
		// a third-best estimate from the second half of the window.
		w.estimates[2] = *NewTypeSample(newSample, newTime)
	}
}

// Resets all estimates to new sample.
func (w *TypeWindowedFilter) Reset(newSample Type, newTime TypeTime) {
	w.estimates[0] = *NewTypeSample(newSample, newTime)
	w.estimates[1] = w.estimates[0]
	w.estimates[2] = w.estimates[0]
}

func (w *TypeWindowedFilter) GetBest() Type       { return w.estimates[0].sample }
func (w *TypeWindowedFilter) GetSecondBest() Type { return w.estimates[1].sample }
func (w *TypeWindowedFilter) GetThirdBest() Type  { return w.estimates[2].sample }


