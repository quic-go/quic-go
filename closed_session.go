package quic

import (
	"sync"

	"github.com/lucas-clemente/quic-go/internal/utils"
)

type closedSession interface {
	destroy()
}

// A closedLocalSession is a session that we closed locally.
// When receiving packets for such a session, we need to retransmit the packet containing the CONNECTION_CLOSE frame,
// with an exponential backoff.
type closedBaseSession struct {
	closeOnce sync.Once
	closeChan chan struct{} // is closed when the session is closed or destroyed

	receivedPackets <-chan *receivedPacket
}

func (s *closedBaseSession) destroy() {
	s.closeOnce.Do(func() {
		close(s.closeChan)
	})
}

func newClosedBaseSession(receivedPackets <-chan *receivedPacket) closedBaseSession {
	return closedBaseSession{
		receivedPackets: receivedPackets,
		closeChan:       make(chan struct{}),
	}
}

type closedLocalSession struct {
	closedBaseSession

	conn            connection
	connClosePacket []byte
	counter         uint64 // number of packets received

	logger utils.Logger
}

// newClosedLocalSession creates a new closedLocalSession and runs it.
func newClosedLocalSession(
	conn connection,
	receivedPackets <-chan *receivedPacket,
	connClosePacket []byte,
	logger utils.Logger,
) closedSession {
	s := &closedLocalSession{
		closedBaseSession: newClosedBaseSession(receivedPackets),
		conn:              conn,
		connClosePacket:   connClosePacket,
		logger:            logger,
	}
	go s.run()
	return s
}

func (s *closedLocalSession) run() {
	for {
		select {
		case p := <-s.receivedPackets:
			s.handlePacket(p)
		case <-s.closeChan:
			return
		}
	}
}

func (s *closedLocalSession) handlePacket(_ *receivedPacket) {
	s.counter++
	// exponential backoff
	// only send a CONNECTION_CLOSE for the 1st, 2nd, 4th, 8th, 16th, ... packet arriving
	for n := s.counter; n > 1; n = n / 2 {
		if n%2 != 0 {
			return
		}
	}
	s.logger.Debugf("Received %d packets after sending CONNECTION_CLOSE. Retransmitting.", s.counter)
	if err := s.conn.Write(s.connClosePacket); err != nil {
		s.logger.Debugf("Error retransmitting CONNECTION_CLOSE: %s", err)
	}
}

// A closedRemoteSession is a session that was closed remotely.
// For such a session, we might receive reordered packets that were sent before the CONNECTION_CLOSE.
// We can just ignore those packets.
type closedRemoteSession struct {
	closedBaseSession
}

var _ closedSession = &closedRemoteSession{}

func newClosedRemoteSession(receivedPackets <-chan *receivedPacket) closedSession {
	s := &closedRemoteSession{
		closedBaseSession: newClosedBaseSession(receivedPackets),
	}
	go s.run()
	return s
}

func (s *closedRemoteSession) run() {
	for {
		select {
		case <-s.receivedPackets: // discard packets
		case <-s.closeChan:
			return
		}
	}
}
