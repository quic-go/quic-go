package quic

import (
	"errors"
	"runtime"

	"golang.org/x/sys/unix"
)

type sendQueue struct {
	queue     chan *packedPacket
	closeChan chan struct{}
	conn      connection
}

func newSendQueue(conn connection) *sendQueue {
	s := &sendQueue{
		conn:      conn,
		closeChan: make(chan struct{}),
		queue:     make(chan *packedPacket, 1),
	}
	return s
}

func (h *sendQueue) Send(p *packedPacket) {
	h.queue <- p
}

func (h *sendQueue) Run() error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	var cpuset unix.CPUSet
	unix.SchedGetaffinity(0, &cpuset)
	if cpuset.Count() <= 0 {
		return errors.New("couldn't get CPU affinity mask")
	}
	cpuset.Zero()
	cpuset.Set(0)
	unix.SchedSetaffinity(0, &cpuset)

	var p *packedPacket
	for {
		select {
		case <-h.closeChan:
			return nil
		case p = <-h.queue:
		}
		if err := h.conn.Write(p.raw); err != nil {
			return err
		}
		p.buffer.Release()
	}
}

func (h *sendQueue) Close() {
	close(h.closeChan)
}
