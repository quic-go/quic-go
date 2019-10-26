package quic

import (
	"fmt"

	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/utils"
	"github.com/lucas-clemente/quic-go/internal/wire"
)

type connIDManager struct {
	queue utils.NewConnectionIDList

	activeSequenceNumber      uint64
	activeConnectionID        protocol.ConnectionID
	activeStatelessResetToken *[16]byte

	addStatelessResetToken func([16]byte)
	queueControlFrame      func(wire.Frame)
}

func newConnIDManager(
	initialDestConnID protocol.ConnectionID,
	addStatelessResetToken func([16]byte),
	queueControlFrame func(wire.Frame),
) *connIDManager {
	return &connIDManager{
		activeConnectionID:     initialDestConnID,
		addStatelessResetToken: addStatelessResetToken,
		queueControlFrame:      queueControlFrame,
	}
}

func (h *connIDManager) Add(f *wire.NewConnectionIDFrame) error {
	if err := h.add(f); err != nil {
		return err
	}
	if h.queue.Len() >= protocol.MaxActiveConnectionIDs {
		h.updateConnectionID()
	}
	return nil
}

func (h *connIDManager) add(f *wire.NewConnectionIDFrame) error {
	// Retire elements in the queue.
	// Doesn't retire the active connection ID.
	var next *utils.NewConnectionIDElement
	for el := h.queue.Front(); el != nil; el = next {
		if el.Value.SequenceNumber >= f.RetirePriorTo {
			break
		}
		next = el.Next()
		h.queueControlFrame(&wire.RetireConnectionIDFrame{
			SequenceNumber: el.Value.SequenceNumber,
		})
		h.queue.Remove(el)
	}

	// insert a new element at the end
	if h.queue.Len() == 0 || h.queue.Back().Value.SequenceNumber < f.SequenceNumber {
		h.queue.PushBack(utils.NewConnectionID{
			SequenceNumber:      f.SequenceNumber,
			ConnectionID:        f.ConnectionID,
			StatelessResetToken: &f.StatelessResetToken,
		})
	} else {
		// insert a new element somewhere in the middle
		for el := h.queue.Front(); el != nil; el = el.Next() {
			if el.Value.SequenceNumber == f.SequenceNumber {
				if !el.Value.ConnectionID.Equal(f.ConnectionID) {
					return fmt.Errorf("received conflicting connection IDs for sequence number %d", f.SequenceNumber)
				}
				if *el.Value.StatelessResetToken != f.StatelessResetToken {
					return fmt.Errorf("received conflicting stateless reset tokens for sequence number %d", f.SequenceNumber)
				}
				break
			}
			if el.Value.SequenceNumber > f.SequenceNumber {
				h.queue.InsertBefore(utils.NewConnectionID{
					SequenceNumber:      f.SequenceNumber,
					ConnectionID:        f.ConnectionID,
					StatelessResetToken: &f.StatelessResetToken,
				}, el)
				break
			}
		}
	}

	// Retire the active connection ID, if necessary.
	if h.activeSequenceNumber < f.RetirePriorTo {
		// The queue is guaranteed to have at least one element at this point.
		h.updateConnectionID()
	}
	return nil
}

func (h *connIDManager) updateConnectionID() {
	h.queueControlFrame(&wire.RetireConnectionIDFrame{
		SequenceNumber: h.activeSequenceNumber,
	})
	front := h.queue.Remove(h.queue.Front())
	h.activeSequenceNumber = front.SequenceNumber
	h.activeConnectionID = front.ConnectionID
	h.activeStatelessResetToken = front.StatelessResetToken
}

// is called when the server performs a Retry
// and when the server changes the connection ID in the first Initial sent
func (h *connIDManager) ChangeInitialConnID(newConnID protocol.ConnectionID) {
	if h.activeSequenceNumber != 0 {
		panic("expected first connection ID to have sequence number 0")
	}
	h.activeConnectionID = newConnID
}

// is called when the server provides a stateless reset token in the transport parameters
func (h *connIDManager) SetStatelessResetToken(token [16]byte) {
	if h.activeSequenceNumber != 0 {
		panic("expected first connection ID to have sequence number 0")
	}
	h.activeStatelessResetToken = &token
	h.addStatelessResetToken(token)
}

func (h *connIDManager) Get() protocol.ConnectionID {
	return h.activeConnectionID
}
