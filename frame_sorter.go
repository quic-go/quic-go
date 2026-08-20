package quic

import (
	"errors"

	"github.com/quic-go/quic-go/internal/protocol"
)

// byteInterval is an interval from one ByteCount to the other
type byteInterval struct {
	Start protocol.ByteCount
	End   protocol.ByteCount
}

type frameSorterEntry struct {
	Data   []byte
	DoneCb func()
}

type frameSorter struct {
	queue   map[protocol.ByteCount]frameSorterEntry
	readPos protocol.ByteCount
	gaps    gapSet
}

var errDuplicateStreamData = errors.New("duplicate stream data")

func newFrameSorter() *frameSorter {
	s := frameSorter{
		queue: make(map[protocol.ByteCount]frameSorterEntry),
	}
	s.gaps.InsertAt(0, byteInterval{Start: 0, End: protocol.MaxByteCount})
	return &s
}

func (s *frameSorter) Push(data []byte, offset protocol.ByteCount, doneCb func()) error {
	err := s.push(data, offset, doneCb)
	if err == errDuplicateStreamData {
		if doneCb != nil {
			doneCb()
		}
		return nil
	}
	return err
}

func (s *frameSorter) push(data []byte, offset protocol.ByteCount, doneCb func()) error {
	if len(data) == 0 {
		return errDuplicateStreamData
	}

	start := offset
	end := offset + protocol.ByteCount(len(data))

	var startGapIndex, endGapIndex int
	var startGap, endGap byteInterval
	var startsInGap, endsInGap bool
	if s.gaps.Len() == 1 {
		startGap = s.gaps.First()
		if startGap.End < start || startGap.Start > end {
			return errDuplicateStreamData
		}
		endGap = startGap
		startsInGap = start >= startGap.Start && start <= startGap.End
		endsInGap = end >= startGap.Start && end < startGap.End
	} else {
		var ok bool
		startGapIndex, endGapIndex, startsInGap, endsInGap, ok = s.gaps.Find(start, end)
		if !ok {
			return errDuplicateStreamData
		}
		startGap = s.gaps.At(startGapIndex)
		endGap = s.gaps.At(endGapIndex)
	}
	startGapEqualsEndGap := startGapIndex == endGapIndex

	if (startGapEqualsEndGap && end <= startGap.Start) ||
		(!startGapEqualsEndGap && startGap.End >= endGap.Start && end <= startGap.Start) {
		return errDuplicateStreamData
	}

	startGapEnd := startGap.End // save it, in case startGap is modified
	endGapStart := endGap.Start // save it, in case endGap is modified
	endGapEnd := endGap.End     // save it, in case endGap is modified
	var adjustedStartGapEnd bool
	var deletedStartGap bool
	var wasCut bool

	pos := start
	var hasReplacedAtLeastOne bool
	for {
		oldEntry, ok := s.queue[pos]
		if !ok {
			break
		}
		oldEntryLen := protocol.ByteCount(len(oldEntry.Data))
		if end-pos > oldEntryLen || (hasReplacedAtLeastOne && end-pos == oldEntryLen) {
			// The existing frame is shorter than the new frame. Replace it.
			delete(s.queue, pos)
			pos += oldEntryLen
			hasReplacedAtLeastOne = true
			if oldEntry.DoneCb != nil {
				oldEntry.DoneCb()
			}
		} else {
			if !hasReplacedAtLeastOne {
				return errDuplicateStreamData
			}
			// The existing frame is longer than the new frame.
			// Cut the new frame such that the end aligns with the start of the existing frame.
			data = data[:pos-start]
			end = pos
			wasCut = true
			break
		}
	}

	if !startsInGap && !hasReplacedAtLeastOne {
		// cut the frame, such that it starts at the start of the gap
		data = data[startGap.Start-start:]
		start = startGap.Start
		wasCut = true
	}
	if start <= startGap.Start {
		if end >= startGap.End {
			// The frame covers the whole startGap. Delete the gap.
			s.gaps.DeleteAt(startGapIndex)
			deletedStartGap = true
		} else {
			startGap.Start = end
			s.gaps.UpdateAt(startGapIndex, startGap)
		}
	} else if !hasReplacedAtLeastOne {
		startGap.End = start
		s.gaps.UpdateAt(startGapIndex, startGap)
		adjustedStartGapEnd = true
	}

	if !startGapEqualsEndGap {
		s.deleteConsecutive(startGapEnd)
		if deletedStartGap {
			endGapIndex--
		} else {
			startGapIndex++
		}
		for startGapIndex < endGapIndex {
			gap := s.gaps.At(startGapIndex)
			if gap.End >= endGapStart {
				break
			}
			s.deleteConsecutive(gap.End)
			s.gaps.DeleteAt(startGapIndex)
			endGapIndex--
		}
	}

	if !endsInGap && start != endGapEnd && end > endGapEnd {
		// cut the frame, such that it ends at the end of the gap
		data = data[:endGapEnd-start]
		end = endGapEnd
		wasCut = true
	}
	if end == endGapEnd {
		if !startGapEqualsEndGap {
			// The frame covers the whole endGap. Delete the gap.
			s.gaps.DeleteAt(endGapIndex)
		}
	} else {
		if startGapEqualsEndGap && adjustedStartGapEnd {
			// The frame split the existing gap into two.
			s.gaps.InsertAt(startGapIndex+1, byteInterval{Start: end, End: startGapEnd})
		} else if !startGapEqualsEndGap {
			endGap.Start = end
			s.gaps.UpdateAt(endGapIndex, endGap)
		}
	}

	if wasCut && len(data) < protocol.MinStreamFrameBufferSize {
		newData := make([]byte, len(data))
		copy(newData, data)
		data = newData
		if doneCb != nil {
			doneCb()
			doneCb = nil
		}
	}

	if s.gaps.Len() > protocol.MaxStreamFrameSorterGaps {
		return errors.New("too many gaps in received data")
	}

	s.queue[start] = frameSorterEntry{Data: data, DoneCb: doneCb}
	return nil
}

// deleteConsecutive deletes consecutive frames from the queue, starting at pos
func (s *frameSorter) deleteConsecutive(pos protocol.ByteCount) {
	for {
		oldEntry, ok := s.queue[pos]
		if !ok {
			break
		}
		oldEntryLen := protocol.ByteCount(len(oldEntry.Data))
		delete(s.queue, pos)
		if oldEntry.DoneCb != nil {
			oldEntry.DoneCb()
		}
		pos += oldEntryLen
	}
}

func (s *frameSorter) Pop() (protocol.ByteCount, []byte, func()) {
	entry, ok := s.queue[s.readPos]
	if !ok {
		return s.readPos, nil, nil
	}
	delete(s.queue, s.readPos)
	offset := s.readPos
	s.readPos += protocol.ByteCount(len(entry.Data))
	if s.gaps.First().End <= s.readPos {
		panic("frame sorter BUG: read position higher than a gap")
	}
	return offset, entry.Data, entry.DoneCb
}

// HasMoreData says if there is any more data queued at *any* offset.
func (s *frameSorter) HasMoreData() bool {
	return len(s.queue) > 0
}

var errTooLittleData = errors.New("too little data")

// Peek copies len(p) consecutive bytes starting at offset into p, without removing them.
// It is only possible to peek from an offset where a frame starts.
//
// If there isn't enough consecutive data available, errTooLittleData is returned.
func (s *frameSorter) Peek(offset protocol.ByteCount, p []byte) error {
	if len(p) == 0 {
		return nil
	}

	// first, check if we have enough consecutive data available
	pos := offset
	remaining := len(p)
	for remaining > 0 {
		entry, ok := s.queue[pos]
		if !ok {
			return errTooLittleData
		}
		entryLen := len(entry.Data)
		if remaining <= entryLen {
			break // enough data available
		}
		remaining -= entryLen
		pos += protocol.ByteCount(entryLen)
	}

	pos = offset
	var copied int
	for copied < len(p) {
		entry := s.queue[pos] // the entry is guaranteed to exist from the check above
		copied += copy(p[copied:], entry.Data)
		pos += protocol.ByteCount(len(entry.Data))
	}
	return nil
}
