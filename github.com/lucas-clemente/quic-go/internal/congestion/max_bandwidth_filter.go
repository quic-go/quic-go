package congestion

type BandwidthCompare func(Bandwidth, Bandwidth) bool

type bandwidthSample struct {
	sample Bandwidth
	time   RoundTripCount
}

func newBandwidthSample(sample Bandwidth, time RoundTripCount) *bandwidthSample {
	return &bandwidthSample{sample: sample, time: time}
}

type MaxBandwidthFilter struct {
	windowLength RoundTripCount
	zeroValue    Bandwidth
	estimates    [3]bandwidthSample
	compare      BandwidthCompare
}

func NewMaxBandwidthFilter(windowLength RoundTripCount, zeroValue Bandwidth, zeroTime RoundTripCount) *MaxBandwidthFilter {
	return &MaxBandwidthFilter{
		windowLength: windowLength,
		zeroValue:    zeroValue,
		estimates:    [3]bandwidthSample{
			*newBandwidthSample(zeroValue, zeroTime),
			*newBandwidthSample(zeroValue, zeroTime),
			*newBandwidthSample(zeroValue, zeroTime),
		},
	}
}
func (w *MaxBandwidthFilter) SetWindowLength(windowLength RoundTripCount) {
	w.windowLength = windowLength
}
func (w *MaxBandwidthFilter) Update(newSample Bandwidth, newTime RoundTripCount) {
	if w.estimates[0].sample == w.zeroValue || w.compare(newSample, w.estimates[0].sample) || RoundTripCount(newTime-w.estimates[2].time) > w.windowLength {
		w.Reset(newSample, newTime)
		return
	}
	if w.compare(newSample, w.estimates[1].sample) {
		w.estimates[1] = *newBandwidthSample(newSample, newTime)
		w.estimates[2] = w.estimates[1]
	} else if w.compare(newSample, w.estimates[2].sample) {
		w.estimates[2] = *newBandwidthSample(newSample, newTime)
	}
	if RoundTripCount(newTime-w.estimates[0].time) > w.windowLength {
		w.estimates[0] = w.estimates[1]
		w.estimates[1] = w.estimates[2]
		w.estimates[2] = *newBandwidthSample(newSample, newTime)
		if RoundTripCount(newTime-w.estimates[0].time) > w.windowLength {
			w.estimates[0] = w.estimates[1]
			w.estimates[1] = w.estimates[2]
		}
		return
	}
	if w.estimates[1].sample == w.estimates[0].sample && RoundTripCount(newTime-w.estimates[1].time) > w.windowLength>>2 {
		w.estimates[2] = *newBandwidthSample(newSample, newTime)
		w.estimates[1] = w.estimates[2]
		return
	}
	if w.estimates[2].sample == w.estimates[1].sample && RoundTripCount(newTime-w.estimates[2].time) > w.windowLength>>1 {
		w.estimates[2] = *newBandwidthSample(newSample, newTime)
	}
}
func (w *MaxBandwidthFilter) Reset(newSample Bandwidth, newTime RoundTripCount) {
	w.estimates[0] = *newBandwidthSample(newSample, newTime)
	w.estimates[1] = w.estimates[0]
	w.estimates[2] = w.estimates[0]
}
func (w *MaxBandwidthFilter) GetBest() Bandwidth {
	return w.estimates[0].sample
}
func (w *MaxBandwidthFilter) GetSecondBest() Bandwidth {
	return w.estimates[1].sample
}
func (w *MaxBandwidthFilter) GetThirdBest() Bandwidth {
	return w.estimates[2].sample
}
