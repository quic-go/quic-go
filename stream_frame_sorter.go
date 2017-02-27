package quic

import (
	"errors"

	"github.com/lucas-clemente/quic-go/frames"
	"github.com/lucas-clemente/quic-go/protocol"
	"github.com/lucas-clemente/quic-go/qerr"
	"github.com/lucas-clemente/quic-go/utils"
)

type streamFrameSorter struct {
	queuedFrames map[protocol.ByteCount]*frames.StreamFrame
	readPosition protocol.ByteCount
	gaps         *utils.ByteIntervalList
}

var (
	errTooManyGapsInReceivedStreamData = errors.New("Too many gaps in received StreamFrame data")
	errDuplicateStreamData             = errors.New("Duplicate Stream Data")
	errEmptyStreamData                 = errors.New("Stream Data empty")
)

func newStreamFrameSorter() *streamFrameSorter {
	s := streamFrameSorter{
		gaps:         utils.NewByteIntervalList(),
		queuedFrames: make(map[protocol.ByteCount]*frames.StreamFrame),
	}
	s.gaps.PushFront(utils.ByteInterval{Start: 0, End: protocol.MaxByteCount})
	return &s
}

func (s *streamFrameSorter) Push(frame *frames.StreamFrame) error {
	if frame.DataLen() == 0 {
		if frame.FinBit {
			s.queuedFrames[frame.Offset] = frame
			return nil
		}
		return errEmptyStreamData
	}

	if _, ok := s.queuedFrames[frame.Offset]; ok {
		return errDuplicateStreamData
	}

	start := frame.Offset
	end := frame.Offset + frame.DataLen()

	if end <= s.gaps.Front().Value.Start {
		return errDuplicateStreamData
	}

	// skip all gaps that are before this stream frame
	var gap *utils.ByteIntervalElement
	for gap = s.gaps.Front(); gap != nil; gap = gap.Next() {
		if end > gap.Value.Start && start <= gap.Value.End {
			break
		}
	}

	if gap == nil {
		return errors.New("StreamFrameSorter BUG: no gap found")
	}

	if start < gap.Value.Start {
		return qerr.Error(qerr.OverlappingStreamData, "start of gap in stream chunk")
	}

	if end > gap.Value.End {
		return qerr.Error(qerr.OverlappingStreamData, "end of gap in stream chunk")
	}

	if start == gap.Value.Start {
		if end == gap.Value.End {
			// the frame completely fills this gap
			// delete the gap
			s.gaps.Remove(gap)
		} else if end < gap.Value.End {
			// the frame covers the beginning of the gap
			// adjust the Start value to shrink the gap
			gap.Value.Start = end
		}
	} else if end == gap.Value.End {
		// the frame covers the end of the gap
		// adjust the End value to shrink the gap
		gap.Value.End = start
	} else {
		// the frame lies within the current gap, splitting it into two
		// insert a new gap and adjust the current one
		intv := utils.ByteInterval{Start: end, End: gap.Value.End}
		s.gaps.InsertAfter(intv, gap)
		gap.Value.End = start
	}

	if s.gaps.Len() > protocol.MaxStreamFrameSorterGaps {
		return errTooManyGapsInReceivedStreamData
	}

	s.queuedFrames[frame.Offset] = frame
	return nil
}

func (s *streamFrameSorter) Pop() *frames.StreamFrame {
	frame := s.Head()
	if frame != nil {
		s.readPosition += frame.DataLen()
		delete(s.queuedFrames, frame.Offset)
	}
	return frame
}

func (s *streamFrameSorter) Head() *frames.StreamFrame {
	frame, ok := s.queuedFrames[s.readPosition]
	if ok {
		return frame
	}
	return nil
}
