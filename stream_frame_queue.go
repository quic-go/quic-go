package quic

import (
	"sync"

	"github.com/lucas-clemente/quic-go/frames"
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
