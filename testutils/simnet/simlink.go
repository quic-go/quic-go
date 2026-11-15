package simnet

import (
	"net"
	"sync"
	"time"
)

// packetWithDeliveryTime holds a packet along with its scheduled delivery time
type packetWithDeliveryTime struct {
	Packet
	DeliveryTime time.Time
}

// LinkSettings defines the network characteristics for a simulated link direction
type LinkSettings struct {
	// MTU (Maximum Transmission Unit) specifies the maximum packet size in bytes
	MTU int
	// Bandwidth in bits per second.
	// Packets wait in a CoDel queue (RFC 8289) that marks ECN-capable packets and drops others.
	// Zero means infinite bandwidth and no queuing.
	Bandwidth int
}

// SimulatedLink simulates a bidirectional network link with variable latency and MTU constraints
type SimulatedLink struct {
	// Internal state for lifecycle management
	wg sync.WaitGroup

	// Queues for packet delivery timing
	downstreamQueue *queue
	upstreamQueue   *queue
	// nil if the bandwidth is infinite
	downstreamCodel *codelQueue
	upstreamCodel   *codelQueue

	// Configuration for link characteristics
	UplinkSettings   LinkSettings
	DownlinkSettings LinkSettings

	// Latency specifies a fixed network delay for downlink packets
	// If both Latency and LatencyFunc are set, LatencyFunc takes precedence
	Latency time.Duration

	// LatencyFunc computes the network delay for each downlink packet
	// This allows variable latency based on packet source/destination
	// If nil, Latency field is used instead
	LatencyFunc func(Packet) time.Duration

	// Packet routing interfaces
	UploadPacket   Router
	downloadPacket PacketReceiver
}

func (l *SimulatedLink) AddNode(addr net.Addr, receiver PacketReceiver) {
	l.downloadPacket = receiver
}

func (l *SimulatedLink) Start() {
	if l.downloadPacket == nil {
		panic("SimulatedLink.Start() called without having added a packet receiver")
	}

	// Sane defaults
	if l.DownlinkSettings.MTU == 0 {
		l.DownlinkSettings.MTU = 1400
	}
	if l.UplinkSettings.MTU == 0 {
		l.UplinkSettings.MTU = 1400
	}

	l.downstreamQueue = newQueue()
	l.upstreamQueue = newQueue()
	if l.DownlinkSettings.Bandwidth > 0 {
		l.downstreamCodel = newCodelQueue(l.DownlinkSettings.MTU)
		l.wg.Go(func() { transmit(l.downstreamCodel, l.DownlinkSettings.Bandwidth, l.enqueueDownstream) })
	}
	if l.UplinkSettings.Bandwidth > 0 {
		l.upstreamCodel = newCodelQueue(l.UplinkSettings.MTU)
		l.wg.Go(func() { transmit(l.upstreamCodel, l.UplinkSettings.Bandwidth, l.enqueueUpstream) })
	}

	l.wg.Go(func() { l.backgroundDownlink() })
	l.wg.Go(func() { l.backgroundUplink() })
}

// transmit sends the packets from q one at a time, at the given bandwidth.
func transmit(q *codelQueue, bandwidth int, send func(Packet)) {
	for {
		p, err := q.Dequeue()
		if err != nil {
			return
		}
		time.Sleep(time.Duration(len(p.Data)*8) * time.Second / time.Duration(bandwidth))
		send(p)
	}
}

func (l *SimulatedLink) Close() error {
	if l.downstreamCodel != nil {
		l.downstreamCodel.Close()
	}
	if l.upstreamCodel != nil {
		l.upstreamCodel.Close()
	}
	l.downstreamQueue.Close()
	l.upstreamQueue.Close()
	l.wg.Wait()
	return nil
}

func (l *SimulatedLink) backgroundDownlink() {
	for {
		// Dequeue a packet (this will block until packet is ready for delivery)
		// Dequeue() returns false when the queue is closed
		p, ok := l.downstreamQueue.Dequeue()
		if !ok {
			return
		}

		// Deliver the packet
		l.downloadPacket.RecvPacket(p.Packet)
	}
}

func (l *SimulatedLink) backgroundUplink() {
	for {
		// Dequeue a packet (this will block until packet is ready for delivery)
		// Dequeue() returns false when the queue is closed
		p, ok := l.upstreamQueue.Dequeue()
		if !ok {
			return
		}

		// Deliver the packet
		_ = l.UploadPacket.SendPacket(p.Packet)
	}
}

func (l *SimulatedLink) SendPacket(p Packet) error {
	if len(p.Data) > l.UplinkSettings.MTU {
		// Drop packet if it's too large
		return nil
	}

	if l.upstreamCodel != nil {
		l.upstreamCodel.Enqueue(p)
		return nil
	}
	l.enqueueUpstream(p)
	return nil
}

func (l *SimulatedLink) enqueueUpstream(p Packet) {
	// Uplink has no latency
	l.upstreamQueue.Enqueue(&packetWithDeliveryTime{
		Packet:       p,
		DeliveryTime: time.Now(),
	})
}

func (l *SimulatedLink) RecvPacket(p Packet) {
	if len(p.Data) > l.DownlinkSettings.MTU {
		// Drop packet if it's too large
		return
	}

	if l.downstreamCodel != nil {
		l.downstreamCodel.Enqueue(p)
		return
	}
	l.enqueueDownstream(p)
}

func (l *SimulatedLink) enqueueDownstream(p Packet) {
	// Calculate delivery time based on downlink latency
	var latency time.Duration
	if l.LatencyFunc != nil {
		latency = l.LatencyFunc(p)
	} else {
		latency = l.Latency
	}
	l.downstreamQueue.Enqueue(&packetWithDeliveryTime{
		Packet:       p,
		DeliveryTime: time.Now().Add(latency),
	})
}
