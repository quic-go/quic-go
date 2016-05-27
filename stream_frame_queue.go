package quic

import (
	"sync"

	"github.com/lucas-clemente/quic-go/frames"
	"github.com/lucas-clemente/quic-go/protocol"
	"github.com/lucas-clemente/quic-go/qerr"
)

var errMapAccess = qerr.Error(qerr.InternalError, "Error accessing the StreamFrameQueue")

// streamFrameQueue is a Queue that handles StreamFrames
type streamFrameQueue struct {
	prioFrames []*frames.StreamFrame
	frameMap   map[protocol.StreamID][]*frames.StreamFrame
	mutex      sync.RWMutex

	activeStreams         []protocol.StreamID
	activeStreamsPosition int

	len     int
	byteLen protocol.ByteCount
}

func newStreamFrameQueue() *streamFrameQueue {
	return &streamFrameQueue{
		frameMap: make(map[protocol.StreamID][]*frames.StreamFrame),
	}
}

// Push adds a new StreamFrame to the queue
func (q *streamFrameQueue) Push(frame *frames.StreamFrame, prio bool) {
	q.mutex.Lock()
	defer q.mutex.Unlock()

	frame.DataLenPresent = true

	if prio {
		q.prioFrames = append(q.prioFrames, frame)
	} else {
		_, streamExisted := q.frameMap[frame.StreamID]
		q.frameMap[frame.StreamID] = append(q.frameMap[frame.StreamID], frame)
		if !streamExisted {
			q.activeStreams = append(q.activeStreams, frame.StreamID)
		}
	}

	q.byteLen += protocol.ByteCount(len(frame.Data))
	q.len++
}

// Len returns the total number of queued StreamFrames
func (q *streamFrameQueue) Len() int {
	q.mutex.RLock()
	defer q.mutex.RUnlock()

	return q.len
}

// ByteLen returns the total number of bytes queued
func (q *streamFrameQueue) ByteLen() protocol.ByteCount {
	q.mutex.RLock()
	defer q.mutex.RUnlock()

	return q.byteLen
}

// Pop returns the next element and deletes it from the queue
func (q *streamFrameQueue) Pop(maxLength protocol.ByteCount) (*frames.StreamFrame, error) {
	q.mutex.Lock()
	defer q.mutex.Unlock()

	var isPrioFrame bool
	var frame *frames.StreamFrame
	var streamID protocol.StreamID
	var err error

	if len(q.prioFrames) > 0 {
		frame = q.prioFrames[0]
		isPrioFrame = true
	} else {
		streamID, err = q.getNextStream()
		if err != nil {
			return nil, err
		}
		if streamID == 0 {
			return nil, nil
		}
		frame = q.frameMap[streamID][0]
	}

	// Does the frame fit into the remaining space?
	frameMinLength, _ := frame.MinLength() // StreamFrame.MinLength *never* returns an error
	if frameMinLength > maxLength {
		return nil, nil
	}

	splitFrame := q.maybeSplitOffFrame(frame, maxLength)

	if splitFrame != nil { // StreamFrame was split
		q.byteLen -= protocol.ByteCount(len(splitFrame.Data))
		return splitFrame, nil
	}

	// StreamFrame was not split. Remove it from the appropriate queue
	if isPrioFrame {
		q.prioFrames = q.prioFrames[1:]
	} else {
		q.frameMap[streamID] = q.frameMap[streamID][1:]
	}

	q.byteLen -= protocol.ByteCount(len(frame.Data))
	q.len--
	return frame, nil
}

// front returns the next element without modifying the queue
// has to be called from a function that has already acquired the mutex
func (q *streamFrameQueue) getNextStream() (protocol.StreamID, error) {
	if q.len-len(q.prioFrames) == 0 {
		return 0, nil
	}

	var counter int
	for counter < len(q.activeStreams) {
		streamID := q.activeStreams[q.activeStreamsPosition]
		frameQueue, ok := q.frameMap[streamID]
		if !ok {
			return 0, errMapAccess
		}
		if len(frameQueue) > 0 {
			q.activeStreamsPosition = (q.activeStreamsPosition + 1) % len(q.activeStreams)
			return streamID, nil
		}
		q.activeStreamsPosition = (q.activeStreamsPosition + 1) % len(q.activeStreams)
		counter++
	}

	return 0, nil
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
