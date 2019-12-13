package quic

import "runtime"

/*
#define _GNU_SOURCE
#include <sched.h>
#include <pthread.h>

void lock_thread(int cpuid) {
		pthread_t tid;
		cpu_set_t cpuset;

		tid = pthread_self();
		CPU_ZERO(&cpuset);
		CPU_SET(cpuid, &cpuset);
    pthread_setaffinity_np(tid, sizeof(cpu_set_t), &cpuset);
}
*/
import "C"

type sendQueue struct {
	queue     chan *packedPacket
	closeChan chan struct{}
	conn      connection
}

func setAffinity() {
	cpuID := C.sched_getcpu()
	runtime.LockOSThread()
	C.lock_thread(C.int(cpuID))
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
	setAffinity()
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
