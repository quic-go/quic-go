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
}

// SimulatedLink simulates a bidirectional network link with variable latency and MTU constraints
type SimulatedLink struct {
	// Internal state for lifecycle management
	wg sync.WaitGroup

	// Queues for packet delivery timing
	downstreamQueue *queue
	upstreamQueue   *queue

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

	l.wg.Add(2)
	go l.backgroundDownlink()
	go l.backgroundUplink()
}

func (l *SimulatedLink) Close() error {
	l.downstreamQueue.Close()
	l.upstreamQueue.Close()
	l.wg.Wait()
	return nil
}

func (l *SimulatedLink) backgroundDownlink() {
	defer l.wg.Done()

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
	defer l.wg.Done()

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

	// Uplink has no latency - packets are delivered immediately
	deliveryTime := time.Now()

	// Enqueue packet with delivery time
	l.upstreamQueue.Enqueue(&packetWithDeliveryTime{
		Packet:       p,
		DeliveryTime: deliveryTime,
	})

	return nil
}

func (l *SimulatedLink) RecvPacket(p Packet) {
	if len(p.Data) > l.DownlinkSettings.MTU {
		// Drop packet if it's too large
		return
	}

	// Calculate delivery time based on downlink latency
	var latency time.Duration
	if l.LatencyFunc != nil {
		latency = l.LatencyFunc(p)
	} else {
		latency = l.Latency
	}
	deliveryTime := time.Now().Add(latency)

	// Enqueue packet with delivery time
	l.downstreamQueue.Enqueue(&packetWithDeliveryTime{
		Packet:       p,
		DeliveryTime: deliveryTime,
	})
}
