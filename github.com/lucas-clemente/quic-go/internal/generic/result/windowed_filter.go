package result

type AckHeightCompare func(protocol.ByteCount, protocol.ByteCount) bool
type ackHeightSample struct {
	sample protocol.ByteCount
	time   RoundTripCount
}

func NewTypeSample(sample protocol.ByteCount, time RoundTripCount) *ackHeightSample {
	return &ackHeightSample{sample: sample, time: time}
}

type MaxAckHeightFilter struct {
	windowLength RoundTripCount
	zeroValue    protocol.ByteCount
	estimates    [3]ackHeightSample
	compare      AckHeightCompare
}

func NewWindowedFilter(window_length_ RoundTripCount, zero_value_ protocol.ByteCount, estimates_ [3]ackHeightSample) *MaxAckHeightFilter {
	return &MaxAckHeightFilter{windowLength: window_length_, zeroValue: zero_value_, estimates: estimates_}
}
func (w *MaxAckHeightFilter) SetWindow_length_(window_length_ RoundTripCount) {
	w.windowLength = window_length_
}
func (w *MaxAckHeightFilter) Update(newSample protocol.ByteCount, newTime RoundTripCount) {
	if w.estimates[0].sample == w.zeroValue || w.compare(newSample, w.estimates[0].sample) || RoundTripCount(newTime-w.estimates[2].time) > w.windowLength {
		w.Reset(newSample, newTime)
		return
	}
	if w.compare(newSample, w.estimates[1].sample) {
		w.estimates[1] = *NewTypeSample(newSample, newTime)
		w.estimates[2] = w.estimates[1]
	} else if w.compare(newSample, w.estimates[2].sample) {
		w.estimates[2] = *NewTypeSample(newSample, newTime)
	}
	if RoundTripCount(newTime-w.estimates[0].time) > w.windowLength {
		w.estimates[0] = w.estimates[1]
		w.estimates[1] = w.estimates[2]
		w.estimates[2] = *NewTypeSample(newSample, newTime)
		if RoundTripCount(newTime-w.estimates[0].time) > w.windowLength {
			w.estimates[0] = w.estimates[1]
			w.estimates[1] = w.estimates[2]
		}
		return
	}
	if w.estimates[1].sample == w.estimates[0].sample && RoundTripCount(newTime-w.estimates[1].time) > w.windowLength>>2 {
		w.estimates[2] = *NewTypeSample(newSample, newTime)
		w.estimates[1] = w.estimates[2]
		return
	}
	if w.estimates[2].sample == w.estimates[1].sample && RoundTripCount(newTime-w.estimates[2].time) > w.windowLength>>1 {
		w.estimates[2] = *NewTypeSample(newSample, newTime)
	}
}
func (w *MaxAckHeightFilter) Reset(newSample protocol.ByteCount, newTime RoundTripCount) {
	w.estimates[0] = *NewTypeSample(newSample, newTime)
	w.estimates[1] = w.estimates[0]
	w.estimates[2] = w.estimates[0]
}
func (w *MaxAckHeightFilter) GetBest() protocol.ByteCount {
	return w.estimates[0].sample
}
func (w *MaxAckHeightFilter) GetSecondBest() protocol.ByteCount {
	return w.estimates[1].sample
}
func (w *MaxAckHeightFilter) GetThirdBest() protocol.ByteCount {
	return w.estimates[2].sample
}
