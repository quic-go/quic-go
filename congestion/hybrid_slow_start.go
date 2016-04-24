package congestion

import "time"

// HybridSlowStart implements the TCP hybrid slow start algorithm
type HybridSlowStart struct {
	endPacketNumber      uint64
	lastSentPacketNumber uint64
	started              bool
	currentMinRTT        time.Duration
	rttSampleCount       uint32
}

// StartReceiveRound is called for the start of each receive round (burst) in the slow start phase.
func (s *HybridSlowStart) StartReceiveRound(last_sent uint64) {
	s.endPacketNumber = last_sent
	s.currentMinRTT = 0
	s.rttSampleCount = 0
	s.started = true
}

// IsEndOfRound returns true if this ack is the last packet number of our current slow start round.
func (s *HybridSlowStart) IsEndOfRound(ack uint64) bool {
	return s.endPacketNumber < ack
}
