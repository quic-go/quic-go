package congestion

import (
	"github.com/lucas-clemente/quic-go/internal/protocol"
)


type AckHeightCompare func(protocol.ByteCount, protocol.ByteCount) bool

type ackHeightSample struct {
	sample protocol.ByteCount
	time   RoundTripCount
}

func newAckHeightSample(sample protocol.ByteCount, time RoundTripCount) *ackHeightSample {
	return &ackHeightSample{sample: sample, time: time}
}

type MaxAckHeightFilter struct {
	windowLength RoundTripCount
	zeroValue    protocol.ByteCount
	estimates    [3]ackHeightSample
	compare      AckHeightCompare
}

func NewMaxAckHeightFilter(windowLength RoundTripCount, zeroValue protocol.ByteCount, zeroTime RoundTripCount) *MaxAckHeightFilter {
	return &MaxAckHeightFilter{
		windowLength: windowLength,
		zeroValue: zeroValue,
		estimates: [3]ackHeightSample{
			*newAckHeightSample(zeroValue, zeroTime),
			*newAckHeightSample(zeroValue, zeroTime),
			*newAckHeightSample(zeroValue, zeroTime),
		},
	}
}
func (w *MaxAckHeightFilter) SetWindowLength(windowLength RoundTripCount) {
	w.windowLength = windowLength
}
func (w *MaxAckHeightFilter) Update(newSample protocol.ByteCount, newTime RoundTripCount) {
	if w.estimates[0].sample == w.zeroValue || w.compare(newSample, w.estimates[0].sample) || RoundTripCount(newTime-w.estimates[2].time) > w.windowLength {
		w.Reset(newSample, newTime)
		return
	}
	if w.compare(newSample, w.estimates[1].sample) {
		w.estimates[1] = *newAckHeightSample(newSample, newTime)
		w.estimates[2] = w.estimates[1]
	} else if w.compare(newSample, w.estimates[2].sample) {
		w.estimates[2] = *newAckHeightSample(newSample, newTime)
	}
	if RoundTripCount(newTime-w.estimates[0].time) > w.windowLength {
		w.estimates[0] = w.estimates[1]
		w.estimates[1] = w.estimates[2]
		w.estimates[2] = *newAckHeightSample(newSample, newTime)
		if RoundTripCount(newTime-w.estimates[0].time) > w.windowLength {
			w.estimates[0] = w.estimates[1]
			w.estimates[1] = w.estimates[2]
		}
		return
	}
	if w.estimates[1].sample == w.estimates[0].sample && RoundTripCount(newTime-w.estimates[1].time) > w.windowLength>>2 {
		w.estimates[2] = *newAckHeightSample(newSample, newTime)
		w.estimates[1] = w.estimates[2]
		return
	}
	if w.estimates[2].sample == w.estimates[1].sample && RoundTripCount(newTime-w.estimates[2].time) > w.windowLength>>1 {
		w.estimates[2] = *newAckHeightSample(newSample, newTime)
	}
}
func (w *MaxAckHeightFilter) Reset(newSample protocol.ByteCount, newTime RoundTripCount) {
	w.estimates[0] = *newAckHeightSample(newSample, newTime)
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
