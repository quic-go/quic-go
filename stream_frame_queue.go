package quic

import (
	"sync"

	"github.com/lucas-clemente/quic-go/frames"
	"github.com/lucas-clemente/quic-go/protocol"
)

// StreamFrameQueue is a Queue that handles StreamFrames
type StreamFrameQueue struct {
	prioFrames []*frames.StreamFrame
	frames     []*frames.StreamFrame
	mutex      sync.Mutex
}

// Push adds a new StreamFrame to the queue
func (q *StreamFrameQueue) Push(frame *frames.StreamFrame, prio bool) {
	q.mutex.Lock()
	defer q.mutex.Unlock()

	if prio {
		q.prioFrames = append(q.prioFrames, frame)
	} else {
		q.frames = append(q.frames, frame)
	}
}

// Len returns the total number of queued StreamFrames
func (q *StreamFrameQueue) Len() int {
	q.mutex.Lock()
	defer q.mutex.Unlock()

	return len(q.prioFrames) + len(q.frames)
}

// ByteLen returns the total number of bytes queued
func (q *StreamFrameQueue) ByteLen() protocol.ByteCount {
	q.mutex.Lock()
	defer q.mutex.Unlock()

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
func (q *StreamFrameQueue) Pop() *frames.StreamFrame {
	q.mutex.Lock()
	defer q.mutex.Unlock()

	if len(q.prioFrames) > 0 {
		frame := q.prioFrames[0]
		q.prioFrames = q.prioFrames[1:]
		return frame
	}
	if len(q.frames) > 0 {
		frame := q.frames[0]
		q.frames = q.frames[1:]
		return frame
	}
	return nil
}

// Front returns the next element without modifying the queue
func (q *StreamFrameQueue) Front() *frames.StreamFrame {
	q.mutex.Lock()
	defer q.mutex.Unlock()

	if len(q.prioFrames) > 0 {
		return q.prioFrames[0]
	}
	if len(q.frames) > 0 {
		return q.frames[0]
	}
	return nil
}
