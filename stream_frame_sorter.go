package quic

import "github.com/lucas-clemente/quic-go/frames"

// TODO: This is currently quite inefficient
type streamFrameSorter struct {
	items []*frames.StreamFrame
}

func (s *streamFrameSorter) Push(val *frames.StreamFrame) {
	for i, f := range s.items {
		if f.Offset > val.Offset {
			// Insert here
			s.items = append(s.items, nil)
			copy(s.items[i+1:], s.items[i:])
			s.items[i] = val
			return
		}
	}
	// Append at the end
	s.items = append(s.items, val)
}

func (s *streamFrameSorter) Pop() *frames.StreamFrame {
	res := s.items[0]
	s.items = s.items[1:]
	return res
}

func (s *streamFrameSorter) Head() *frames.StreamFrame {
	if len(s.items) > 0 {
		return s.items[0]
	}
	return nil
}
