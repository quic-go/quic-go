package proxy

import (
	"math/rand"
	"time"
)

type rttGenerator struct {
	min time.Duration
	max time.Duration
}

func newRttGenerator(min, max time.Duration) rttGenerator {
	rand.Seed(time.Now().UnixNano())
	return rttGenerator{
		min: min,
		max: max,
	}
}

func (s *rttGenerator) getRTT() time.Duration {
	if s.min == s.max {
		return s.min
	}

	minns := s.min.Nanoseconds()
	maxns := s.max.Nanoseconds()
	rttns := rand.Int63n(maxns-minns) + minns

	return time.Duration(rttns) * time.Nanosecond
}
