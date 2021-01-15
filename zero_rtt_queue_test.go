package quic

import (
	"encoding/binary"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/lucas-clemente/quic-go/internal/protocol"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("0-RTT queue", func() {
	var q *zeroRTTQueue
	queueDuration := scaleDuration(50 * time.Millisecond)

	getQueuedPackets := func(connID protocol.ConnectionID) []*receivedPacket {
		var packets []*receivedPacket
		sess := NewMockPacketHandler(mockCtrl)
		sess.EXPECT().handlePacket(gomock.Any()).Do(func(p *receivedPacket) {
			packets = append(packets, p)
		}).AnyTimes()
		q.DequeueToSession(connID, sess)
		return packets
	}

	BeforeEach(func() {
		q = newZeroRTTQueue()
		q.queueDuration = queueDuration
	})

	AfterEach(func() {
		// dequeue all packets to make sure the timers are stopped
		q.mutex.Lock()
		for connID := range q.queue {
			sess := NewMockPacketHandler(mockCtrl)
			sess.EXPECT().handlePacket(gomock.Any()).AnyTimes()
			q.dequeueToSession(protocol.ConnectionID(connID), sess)
		}
		q.mutex.Unlock()
	})

	It("stores a 0-RTT packet", func() {
		connID := protocol.ConnectionID{0xde, 0xad, 0xbe, 0xef}
		p := &receivedPacket{data: []byte("foobar")}
		q.Enqueue(connID, p)
		queuedPackets := getQueuedPackets(connID)
		Expect(queuedPackets).To(Equal([]*receivedPacket{p}))
	})

	It("doesn't dequeue for unknown connection IDs", func() {
		Expect(getQueuedPackets(protocol.ConnectionID{0x42})).To(BeEmpty())
	})

	It("only stores packets for Max0RTTQueues connection", func() {
		getConnID := func(i int) protocol.ConnectionID {
			connID := make([]byte, 4)
			binary.BigEndian.PutUint32(connID, uint32(i))
			return connID
		}

		// fill up the queues
		for i := 0; i < protocol.Max0RTTQueues; i++ {
			connID := getConnID(i)
			q.Enqueue(connID, &receivedPacket{data: []byte(connID)})
		}
		// now try to enqueue a packet for another connection ID
		connID := protocol.ConnectionID{0xde, 0xad, 0xbe, 0xef}
		q.Enqueue(connID, &receivedPacket{data: []byte("foobar")})
		// check that the other queues were all saved
		for i := 0; i < protocol.Max0RTTQueues; i++ {
			queuedPackets := getQueuedPackets(getConnID(i))
			Expect(queuedPackets).To(HaveLen(1))
			Expect(binary.BigEndian.Uint32(queuedPackets[0].data)).To(BeEquivalentTo(i))
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
		Expect(getQueuedPackets(connID)).To(BeEmpty())
		// dequeue the packet from the first queue
		Expect(getQueuedPackets(protocol.ConnectionID{0, 0, 0, 0})).ToNot(BeNil())
		// now it should be possible to queue another packet
		q.Enqueue(connID, &receivedPacket{data: []byte("foobar")})
		Expect(getQueuedPackets(connID)).ToNot(BeNil())
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
		queuedPackets := getQueuedPackets(connID)
		Expect(queuedPackets).To(HaveLen(protocol.Max0RTTQueueLen))
		for i, p := range queuedPackets {
			Expect(binary.BigEndian.Uint32(p.data)).To(BeEquivalentTo(i))
		}
	})

	It("deletes packets if they aren't dequeued after a short while", func() {
		connID := protocol.ConnectionID{0xde, 0xad, 0xbe, 0xef}
		p := &receivedPacket{data: []byte("foobar"), buffer: getPacketBuffer()}
		q.Enqueue(connID, p)
		time.Sleep(queueDuration * 3 / 2)
		Expect(getQueuedPackets(connID)).To(BeNil())
	})
})
