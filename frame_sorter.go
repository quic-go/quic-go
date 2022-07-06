package quic

import (
	"errors"

	"github.com/lucas-clemente/quic-go/internal/utils"
	"github.com/lucas-clemente/quic-go/internal/utils/tree"

	"github.com/lucas-clemente/quic-go/internal/protocol"
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
	gapTree *tree.Btree
}

var errDuplicateStreamData = errors.New("duplicate stream data")

func newFrameSorter() *frameSorter {
	s := frameSorter{
		gapTree: tree.New(),
		queue:   make(map[protocol.ByteCount]frameSorterEntry),
	}
	s.gapTree.Insert(&utils.ByteInterval{Start: 0, End: protocol.MaxByteCount})
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
	covInterval := &utils.ByteInterval{Start: start, End: end}

	gaps := s.gapTree.Match(covInterval)

	if len(gaps) == 0 {
		// no overlap with any existing gap
		return errDuplicateStreamData
	}

	startGap := gaps[0].(*utils.ByteInterval)
	endGap := gaps[len(gaps)-1].(*utils.ByteInterval)
	startGapEqualsEndGap := len(gaps) == 1

	if startGapEqualsEndGap && end <= startGap.Start {
		return errDuplicateStreamData
	}

	startsInGap := covInterval.Start >= startGap.Start && covInterval.Start <= startGap.End
	endsInGap := covInterval.End >= endGap.Start && covInterval.End < endGap.End

	startGapEnd := startGap.End // save it, in case startGap is modified
	endGapStart := endGap.Start // save it, in case endGap is modified
	endGapEnd := endGap.End     // save it, in case endGap is modified
	var adjustedStartGapEnd bool
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
			s.gapTree.Delete(startGap)
		} else {
			s.gapTree.Delete(startGap)
			startGap.Start = end
			// Re-insert the gap, but with the new start.
			s.gapTree.Insert(startGap)
		}
	} else if !hasReplacedAtLeastOne {
		s.gapTree.Delete(startGap)
		startGap.End = start
		// Re-insert the gap, but with the new end.
		s.gapTree.Insert(startGap)
		adjustedStartGapEnd = true
	}

	if !startGapEqualsEndGap {
		s.deleteConsecutive(startGapEnd)
		for _, gap := range gaps[1:] {
			g := gap.(*utils.ByteInterval)
			if g.End >= endGapStart {
				break
			}
			s.deleteConsecutive(g.End)
			s.gapTree.Delete(gap)
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
			s.gapTree.Delete(endGap)
		}
	} else {
		if startGapEqualsEndGap && adjustedStartGapEnd {
			// The frame split the existing gap into two.
			s.gapTree.Insert(&utils.ByteInterval{Start: end, End: startGapEnd})
		} else if !startGapEqualsEndGap {
			s.gapTree.Delete(endGap)
			endGap.Start = end
			// Re-insert the gap, but with the new start.
			s.gapTree.Insert(endGap)
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

	if s.gapTree.Len() > protocol.MaxStreamFrameSorterGaps {
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
	return offset, entry.Data, entry.DoneCb
}

// HasMoreData says if there is any more data queued at *any* offset.
func (s *frameSorter) HasMoreData() bool {
	return len(s.queue) > 0
}
