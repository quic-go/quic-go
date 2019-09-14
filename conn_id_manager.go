package quic

import (
	"fmt"

	"github.com/lucas-clemente/quic-go/internal/utils"
	"github.com/lucas-clemente/quic-go/internal/wire"
)

type connIDManager struct {
	queue utils.NewConnectionIDList

	queueControlFrame func(wire.Frame)
}

func newConnIDManager(queueControlFrame func(wire.Frame)) *connIDManager {
	return &connIDManager{queueControlFrame: queueControlFrame}
}

func (h *connIDManager) Add(f *wire.NewConnectionIDFrame) error {
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
		return nil
	}
	// insert a new element somewhere in the middle
	for el := h.queue.Front(); el != nil; el = el.Next() {
		if el.Value.SequenceNumber == f.SequenceNumber {
			if !el.Value.ConnectionID.Equal(f.ConnectionID) {
				return fmt.Errorf("received conflicting connection IDs for sequence number %d", f.SequenceNumber)
			}
			if *el.Value.StatelessResetToken != f.StatelessResetToken {
				return fmt.Errorf("received conflicting stateless reset tokens for sequence number %d", f.SequenceNumber)
			}
			return nil
		}
		if el.Value.SequenceNumber > f.SequenceNumber {
			h.queue.InsertBefore(utils.NewConnectionID{
				SequenceNumber:      f.SequenceNumber,
				ConnectionID:        f.ConnectionID,
				StatelessResetToken: &f.StatelessResetToken,
			}, el)
			return nil
		}
	}
	panic("should have processed NEW_CONNECTION_ID frame")
}
