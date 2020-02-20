package quic

import (
	"encoding/binary"
	"time"

	"github.com/lucas-clemente/quic-go/internal/protocol"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("0-RTT queue", func() {
	var q *zeroRTTQueue

	BeforeEach(func() {
		q = newZeroRTTQueue()
	})

	AfterEach(func() {
		// dequeue all packets to make sure the timers are stopped
		q.mutex.Lock()
		for connID := range q.queue {
			for {
				q.mutex.Unlock()
				p := q.Dequeue(protocol.ConnectionID(connID))
				q.mutex.Lock()
				if p != nil {
					break
				}
			}
		}
		q.mutex.Unlock()
	})

	It("stores a 0-RTT packet", func() {
		connID := protocol.ConnectionID{0xde, 0xad, 0xbe, 0xef}
		p := &receivedPacket{data: []byte("foobar")}
		q.Enqueue(connID, p)
		Expect(q.Dequeue(connID)).To(Equal(p))
		Expect(q.Dequeue(connID)).To(BeNil())
	})

	It("returns a nil packet for unknown connection IDs", func() {
		Expect(q.Dequeue(protocol.ConnectionID{0x42})).To(BeNil())
	})

	It("only stores packets for Max0RTTQueues connection", func() {
		// fill up the queues
		for i := 0; i < protocol.Max0RTTQueues; i++ {
			data := make([]byte, 4)
			binary.BigEndian.PutUint32(data, uint32(i))
			q.Enqueue(protocol.ConnectionID(data), &receivedPacket{data: data})
		}
		// now try to enqueue a packet for another connection ID
		connID := protocol.ConnectionID{0xde, 0xad, 0xbe, 0xef}
		q.Enqueue(connID, &receivedPacket{data: []byte("foobar")})
		Expect(q.Dequeue(connID)).To(BeNil())
		// check that the other queues were all saved
		for i := 0; i < protocol.Max0RTTQueues; i++ {
			connID := make([]byte, 4)
			binary.BigEndian.PutUint32(connID, uint32(i))
			p := q.Dequeue(connID)
			Expect(p).ToNot(BeNil())
			Expect(binary.BigEndian.Uint32(p.data)).To(BeEquivalentTo(i))
		}
	})

	It("removes queues when packets are dequeued", func() {
		// fill up the queues
		for i := 0; i < protocol.Max0RTTQueues; i++ {
			data := make([]byte, 4)
			binary.BigEndian.PutUint32(data, uint32(i))
			q.Enqueue(protocol.ConnectionID(data), &receivedPacket{data: data})
		}
		// now try to enqueue a packet for another connection ID
		connID := protocol.ConnectionID{0xde, 0xad, 0xbe, 0xef}
		q.Enqueue(connID, &receivedPacket{data: []byte("foobar")})
		Expect(q.Dequeue(connID)).To(BeNil())
		// dequeue the packet from the first queue
		Expect(q.Dequeue(protocol.ConnectionID{0, 0, 0, 0})).ToNot(BeNil())
		// now it should be possible to queue another packet
		q.Enqueue(connID, &receivedPacket{data: []byte("foobar")})
		Expect(q.Dequeue(connID)).ToNot(BeNil())
	})

	It("limits the number of packets it stores for one connection", func() {
		connID := protocol.ConnectionID{0xde, 0xad, 0xbe, 0xef}
		// fill up the queue
		for i := 0; i < protocol.Max0RTTQueueLen; i++ {
			data := make([]byte, 4)
			binary.BigEndian.PutUint32(data, uint32(i))
			q.Enqueue(connID, &receivedPacket{data: data})
		}
		// The queue is full now. This packet will be dropped.
		q.Enqueue(connID, &receivedPacket{data: []byte("foobar")})
		for i := 0; i < protocol.Max0RTTQueueLen; i++ {
			p := q.Dequeue(connID)
			Expect(p).ToNot(BeNil())
			Expect(binary.BigEndian.Uint32(p.data)).To(BeEquivalentTo(i))
		}
		// The queue should now be empty.
		Expect(q.Dequeue(connID)).To(BeNil())
	})

	It("deletes packets if they aren't dequeued after a short while", func() {
		connID := protocol.ConnectionID{0xde, 0xad, 0xbe, 0xef}
		p := &receivedPacket{data: []byte("foobar"), buffer: getPacketBuffer()}
		q.Enqueue(connID, p)
		time.Sleep(protocol.Max0RTTQueueingDuration * 3 / 2)
		Expect(q.Dequeue(connID)).To(BeNil())
	})
})
