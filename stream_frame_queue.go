package quic

import (
	"sync"

	"github.com/lucas-clemente/quic-go/frames"
	"github.com/lucas-clemente/quic-go/protocol"
)

// streamFrameQueue is a Queue that handles StreamFrames
type streamFrameQueue struct {
	prioFrames []*frames.StreamFrame
	frames     []*frames.StreamFrame
	mutex      sync.RWMutex
}

// Push adds a new StreamFrame to the queue
func (q *streamFrameQueue) Push(frame *frames.StreamFrame, prio bool) {
	q.mutex.Lock()
	defer q.mutex.Unlock()

	frame.DataLenPresent = true

	if prio {
		q.prioFrames = append(q.prioFrames, frame)
	} else {
		q.frames = append(q.frames, frame)
	}
}

// Len returns the total number of queued StreamFrames
func (q *streamFrameQueue) Len() int {
	q.mutex.RLock()
	defer q.mutex.RUnlock()

	return len(q.prioFrames) + len(q.frames)
}

// ByteLen returns the total number of bytes queued
func (q *streamFrameQueue) ByteLen() protocol.ByteCount {
	q.mutex.RLock()
	defer q.mutex.RUnlock()

	// TODO: improve performance
	// This is a very unperformant implementation. However, the obvious solution of keeping track of the length on Push() and Pop() doesn't work, since the front frame can be split by the PacketPacker

	var length protocol.ByteCount
	for _, frame := range q.prioFrames {
		length += protocol.ByteCount(len(frame.Data))
	}
	for _, frame := range q.frames {
		length += protocol.ByteCount(len(frame.Data))
	}
	return length
}

// Pop returns the next element and deletes it from the queue
func (q *streamFrameQueue) Pop(maxLength protocol.ByteCount) *frames.StreamFrame {
	q.mutex.Lock()
	defer q.mutex.Unlock()

	frame, isPrioFrame := q.front()
	if frame == nil {
		return nil
	}

	// Does the frame fit into the remaining space?
	frameMinLength, _ := frame.MinLength() // StreamFrame.MinLength *never* returns an error
	if frameMinLength > maxLength {
		return nil
	}

	splitFrame := q.maybeSplitOffFrame(frame, maxLength)

	if splitFrame != nil { // StreamFrame was split
		return splitFrame
	}

	// StreamFrame was not split. Remove it from the appropriate queue
	if isPrioFrame {
		q.prioFrames = q.prioFrames[1:]
	} else {
		q.frames = q.frames[1:]
	}

	return frame
}

// front returns the next element without modifying the queue
// has to be called from a function that has already acquired the mutex
func (q *streamFrameQueue) front() (*frames.StreamFrame, bool) {
	if len(q.prioFrames) > 0 {
		return q.prioFrames[0], true
	}
	if len(q.frames) > 0 {
		return q.frames[0], false
	}
	return nil, false
}

// maybeSplitOffFrame removes the first n bytes and returns them as a separate frame. If n >= len(n), nil is returned and nothing is modified.
// has to be called from a function that has already acquired the mutex
func (q *streamFrameQueue) maybeSplitOffFrame(frame *frames.StreamFrame, n protocol.ByteCount) *frames.StreamFrame {
	minLength, _ := frame.MinLength() // StreamFrame.MinLength *never* errors
	if n >= minLength-1+protocol.ByteCount(len(frame.Data)) {
		return nil
	}
	n -= minLength - 1

	defer func() {
		frame.Data = frame.Data[n:]
		frame.Offset += n
	}()

	return &frames.StreamFrame{
		FinBit:         false,
		StreamID:       frame.StreamID,
		Offset:         frame.Offset,
		Data:           frame.Data[:n],
		DataLenPresent: frame.DataLenPresent,
	}
}
