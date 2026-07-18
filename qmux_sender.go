package quic

import (
	"net"
	"sync"
	"time"

	"github.com/quic-go/quic-go/internal/protocol"
)

type qmuxSender struct {
	queue       chan qmuxOutboundRecord
	closeCalled chan struct{}
	runStopped  chan struct{}
	available   chan struct{}
	conn        sendConn
	state       *qmuxState
	mutex       sync.Mutex
	stopped     bool
}

var _ sender = &qmuxSender{}

func newQMuxSender(conn sendConn, state *qmuxState) sender {
	return &qmuxSender{
		conn:        conn,
		state:       state,
		runStopped:  make(chan struct{}),
		closeCalled: make(chan struct{}),
		available:   make(chan struct{}, 1),
		queue:       make(chan qmuxOutboundRecord, sendQueueCapacity),
	}
}

type qmuxOutboundRecord struct {
	buf        *packetBuffer
	gsoSize    uint16
	ecn        protocol.ECN
	completion qmuxWrittenFrameBatch
}

func (s *qmuxSender) Send(p *packetBuffer, gsoSize uint16, ecn protocol.ECN) {
	s.send(qmuxOutboundRecord{buf: p, gsoSize: gsoSize, ecn: ecn})
}

func (s *qmuxSender) sendRecord(record qmuxOutboundRecord) {
	s.send(record)
}

func (s *qmuxSender) send(record qmuxOutboundRecord) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	if s.stopped {
		record.buf.Release()
		return
	}
	select {
	case s.queue <- record:
		if len(s.queue) == sendQueueCapacity {
			select {
			case <-s.available:
			default:
			}
		}
	default:
		panic("qmuxSender.Send would have blocked")
	}
}

func (s *qmuxSender) SendProbe(p *packetBuffer, _ net.Addr, _ packetInfo) {
	p.Release()
}

func (s *qmuxSender) Run() error {
	var shouldClose bool
	for {
		if shouldClose && s.stopIfDrained() {
			return nil
		}
		select {
		case <-s.closeCalled:
			s.closeCalled = nil
			shouldClose = true
		case e := <-s.queue:
			if err := s.conn.Write(e.buf.Data, e.gsoSize, e.ecn); err != nil {
				e.buf.Release()
				s.mutex.Lock()
				s.stopped = true
				close(s.runStopped)
				for len(s.queue) > 0 {
					(<-s.queue).buf.Release()
				}
				s.mutex.Unlock()
				return err
			}
			s.state.queueWrittenFrameBatch(e.completion)
			e.buf.Release()
			select {
			case s.available <- struct{}{}:
			default:
			}
		}
	}
}

func (s *qmuxSender) stopIfDrained() bool {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	if len(s.queue) > 0 {
		return false
	}
	s.stopped = true
	close(s.runStopped)
	return true
}

func (s *qmuxSender) WouldBlock() bool {
	return len(s.queue) == sendQueueCapacity
}

func (s *qmuxSender) Available() <-chan struct{} {
	return s.available
}

func (s *qmuxSender) Close() {
	// Bound the writes of any remaining queued records: the peer may have stopped reading,
	// and connection teardown must not block indefinitely on the underlying transport.
	if conn, ok := s.conn.(*qmuxSendConn); ok {
		_ = conn.setWriteDeadline(time.Now().Add(time.Second))
	}
	close(s.closeCalled)
	<-s.runStopped
}
