package quic

import "github.com/quic-go/quic-go/internal/protocol"

const gapInlineCapacity = 8

// gapSet stores disjoint intervals ordered by Start. This invariant also orders
// End, allowing binary search on either boundary once the inline store fills.
type gapSet struct {
	length int
	inline [gapInlineCapacity]byteInterval
	large  []byteInterval
}

func (s *gapSet) Len() int { return s.length }

func (s *gapSet) First() byteInterval { return s.values()[0] }

func (s *gapSet) At(index int) byteInterval { return s.values()[index] }

func (s *gapSet) Find(start, end protocol.ByteCount) (
	startIndex, endIndex int,
	startsInGap, endsInGap, ok bool,
) {
	values := s.values()
	if len(values) == 1 {
		gap := values[0]
		if gap.End < start || gap.Start > end {
			return 0, 0, false, false, false
		}
		return 0, 0, start >= gap.Start, end >= gap.Start && end < gap.End, true
	}

	if len(values) <= gapInlineCapacity {
		for startIndex < len(values) && values[startIndex].End < start {
			startIndex++
		}
	} else {
		low, high := 0, len(values)
		for low < high {
			middle := int(uint(low+high) >> 1)
			if values[middle].End < start {
				low = middle + 1
			} else {
				high = middle
			}
		}
		startIndex = low
	}
	if startIndex == len(values) || values[startIndex].Start > end {
		return 0, 0, false, false, false
	}

	if len(values) <= gapInlineCapacity {
		endIndex = startIndex
		for endIndex+1 < len(values) && values[endIndex+1].Start <= end {
			endIndex++
		}
	} else {
		low, high := startIndex, len(values)
		for low < high {
			middle := int(uint(low+high) >> 1)
			if values[middle].Start <= end {
				low = middle + 1
			} else {
				high = middle
			}
		}
		endIndex = low - 1
	}
	startGap, endGap := values[startIndex], values[endIndex]
	return startIndex, endIndex,
		start >= startGap.Start && start <= startGap.End,
		end >= endGap.Start && end < endGap.End,
		true
}

func (s *gapSet) InsertAt(index int, value byteInterval) {
	if s.length < gapInlineCapacity {
		copy(s.inline[index+1:s.length+1], s.inline[index:s.length])
		s.inline[index] = value
		s.length++
		return
	}
	if s.length == gapInlineCapacity {
		if cap(s.large) < 2*gapInlineCapacity {
			s.large = make([]byteInterval, s.length+1, 2*gapInlineCapacity)
		} else {
			s.large = s.large[:s.length+1]
		}
		copy(s.large, s.inline[:])
	} else {
		s.large = append(s.large, byteInterval{})
	}
	copy(s.large[index+1:], s.large[index:s.length])
	s.large[index] = value
	s.length++
}

func (s *gapSet) DeleteAt(index int) {
	values := s.values()
	copy(values[index:], values[index+1:])
	s.length--
	values[s.length] = byteInterval{}
	if len(values) > gapInlineCapacity && s.length == gapInlineCapacity {
		copy(s.inline[:], values[:gapInlineCapacity])
		s.large = s.large[:0]
	} else if len(values) > gapInlineCapacity {
		s.large = s.large[:s.length]
	}
}

func (s *gapSet) UpdateAt(index int, value byteInterval) {
	s.values()[index] = value
}

func (s *gapSet) values() []byteInterval {
	if s.length <= gapInlineCapacity {
		return s.inline[:s.length]
	}
	return s.large[:s.length]
}
