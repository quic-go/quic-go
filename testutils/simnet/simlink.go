package simnet

import (
	"context"
	"net"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// Creates a new RateLimiter with the following parameters:
// bandwidth (in bits/sec).
// burstSize is in Bytes
func newRateLimiter(bandwidth int, burstSize int) *rate.Limiter {
	// Convert bandwidth from bits/sec to bytes/sec
	bytesPerSecond := rate.Limit(float64(bandwidth) / 8.0)
	return rate.NewLimiter(bytesPerSecond, burstSize)
}

// packetWithDeliveryTime holds a packet along with its delivery time and enqueue time
type packetWithDeliveryTime struct {
	Packet
	DeliveryTime time.Time
}

// LinkSettings defines the network characteristics for a simulated link direction
type LinkSettings struct {
	// BitsPerSecond specifies the bandwidth limit in bits per second
	BitsPerSecond int

	// MTU (Maximum Transmission Unit) specifies the maximum packet size in bytes
	MTU int
}

// SimulatedLink simulates a bidirectional network link with variable latency,
// bandwidth limiting, and CoDel-based bufferbloat mitigation
type SimulatedLink struct {
	// Internal state for lifecycle management
	closed chan struct{}
	wg     sync.WaitGroup

	// CoDel queues for bufferbloat control
	downstreamQueue *codelQueue
	upstreamQueue   *codelQueue

	// Rate limiters enforce bandwidth constraints
	upLimiter   *rate.Limiter
	downLimiter *rate.Limiter

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

	l.closed = make(chan struct{})

	// Sane defaults
	if l.DownlinkSettings.MTU == 0 {
		l.DownlinkSettings.MTU = 1400
	}
	if l.UplinkSettings.MTU == 0 {
		l.UplinkSettings.MTU = 1400
	}

	// Initialize CoDel queues with 5ms target and 100ms interval
	const target = 5 * time.Millisecond
	const interval = 100 * time.Millisecond
	l.downstreamQueue = newCodelQueue(target, interval)
	l.upstreamQueue = newCodelQueue(target, interval)

	// Initialize rate limiters
	const burstSizeInPackets = 16
	l.upLimiter = newRateLimiter(l.UplinkSettings.BitsPerSecond, l.UplinkSettings.MTU*burstSizeInPackets)
	l.downLimiter = newRateLimiter(l.DownlinkSettings.BitsPerSecond, l.DownlinkSettings.MTU*burstSizeInPackets)

	l.wg.Add(2)
	go l.backgroundDownlink()
	go l.backgroundUplink()
}

func (l *SimulatedLink) Close() error {
	close(l.closed)
	l.downstreamQueue.Close()
	l.upstreamQueue.Close()
	l.wg.Wait()
	return nil
}

func (l *SimulatedLink) backgroundDownlink() {
	defer l.wg.Done()

	for {
		select {
		case <-l.closed:
			return
		default:
		}

		// Dequeue a packet (this will block until packet is ready for delivery)
		p, ok := l.downstreamQueue.Dequeue()
		if !ok {
			return
		}

		// Calculate sojourn time (time spent in queue)
		sojournTime := time.Since(p.DeliveryTime)

		// Check if CoDel wants to drop this packet
		shouldDrop := l.downstreamQueue.shouldDrop(sojournTime)
		if shouldDrop {
			// Drop the packet and continue to next one
			continue
		}

		// Apply rate limiting before delivery
		l.downLimiter.WaitN(context.Background(), len(p.Data))

		// Deliver the packet
		l.downloadPacket.RecvPacket(p.Packet)
	}
}

func (l *SimulatedLink) backgroundUplink() {
	defer l.wg.Done()

	for {
		select {
		case <-l.closed:
			return
		default:
		}

		// Dequeue a packet (this will block until packet is ready for delivery)
		p, ok := l.upstreamQueue.Dequeue()
		if !ok {
			return
		}

		// Calculate sojourn time (time spent in queue)
		sojournTime := time.Since(p.DeliveryTime)

		// Check if CoDel wants to drop this packet
		shouldDrop := l.upstreamQueue.shouldDrop(sojournTime)
		if shouldDrop {
			// Drop the packet and continue to next one
			continue
		}

		// Apply rate limiting before delivery
		l.upLimiter.WaitN(context.Background(), len(p.Data))

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

	// Enqueue packet with delivery time to CoDel queue
	// Rate limiting happens after dequeue in background goroutine
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

	// Enqueue packet with delivery time to CoDel queue
	// Rate limiting happens after dequeue in background goroutine
	l.downstreamQueue.Enqueue(&packetWithDeliveryTime{
		Packet:       p,
		DeliveryTime: deliveryTime,
	})
}
