package quic

import (
	"sync"

	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/utils"
)

type closedLocalSession struct {
	conn            connection
	connClosePacket []byte

	closeOnce sync.Once
	closeChan chan struct{} // is closed when the session is closed or destroyed

	receivedPackets chan *receivedPacket
	counter         uint64 // number of packets received

	perspective protocol.Perspective

	logger utils.Logger
}

var _ packetHandler = &closedLocalSession{}

// newClosedLocalSession creates a new closedLocalSession and runs it.
func newClosedLocalSession(
	conn connection,
	connClosePacket []byte,
	perspective protocol.Perspective,
	logger utils.Logger,
) packetHandler {
	s := &closedLocalSession{
		conn:            conn,
		connClosePacket: connClosePacket,
		perspective:     perspective,
		logger:          logger,
		closeChan:       make(chan struct{}),
		receivedPackets: make(chan *receivedPacket, 64),
	}
	go s.run()
	return s
}

func (s *closedLocalSession) run() {
	for {
		select {
		case p := <-s.receivedPackets:
			s.handlePacketImpl(p)
		case <-s.closeChan:
			return
		}
	}
}

func (s *closedLocalSession) handlePacket(p *receivedPacket) {
	select {
	case s.receivedPackets <- p:
	default:
	}
}

func (s *closedLocalSession) handlePacketImpl(p *receivedPacket) {
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

func (s *closedLocalSession) Close() error {
	s.destroy(nil)
	return nil
}

func (s *closedLocalSession) destroy(error) {
	s.closeOnce.Do(func() {
		close(s.closeChan)
	})
}

func (s *closedLocalSession) getPerspective() protocol.Perspective {
	return s.perspective
}
