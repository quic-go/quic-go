package simnet

import (
	"errors"
	"net"
	"net/netip"
	"sync"
	"time"
)

type ipPortKey struct {
	ip    string
	port  uint16
	isUDP bool
}

func (k *ipPortKey) FromNetAddr(addr net.Addr) error {
	switch addr := addr.(type) {
	case *net.UDPAddr:
		*k = ipPortKey{
			ip:    string(addr.IP),
			port:  uint16(addr.Port),
			isUDP: true,
		}
		return nil
	case *net.TCPAddr:
		*k = ipPortKey{
			ip:    string(addr.IP),
			port:  uint16(addr.Port),
			isUDP: false,
		}
		return nil
	default:
		ip, err := netip.ParseAddrPort(addr.String())
		if err != nil {
			return err
		}
		*k = ipPortKey{
			ip:    string(ip.Addr().AsSlice()),
			port:  ip.Port(),
			isUDP: addr.Network() == "udp",
		}
		return nil
	}
}

type addrMap[V any] struct {
	mu    sync.Mutex
	nodes map[ipPortKey]V
}

func (m *addrMap[V]) Get(addr net.Addr) (V, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var v V
	if len(m.nodes) == 0 {
		return v, false
	}
	var k ipPortKey
	if err := k.FromNetAddr(addr); err != nil {
		return v, false
	}
	v, ok := m.nodes[k]
	return v, ok
}

func (m *addrMap[V]) Set(addr net.Addr, v V) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.nodes == nil {
		m.nodes = make(map[ipPortKey]V)
	}

	var k ipPortKey
	if err := k.FromNetAddr(addr); err != nil {
		return err
	}
	m.nodes[k] = v
	return nil
}

func (m *addrMap[V]) Delete(addr net.Addr) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.nodes == nil {
		m.nodes = make(map[ipPortKey]V)
	}

	var k ipPortKey
	if err := k.FromNetAddr(addr); err != nil {
		return err
	}
	delete(m.nodes, k)
	return nil
}

// PerfectRouter is a router that has no latency or jitter and can route to
// every node
type PerfectRouter struct {
	nodes addrMap[PacketReceiver]
}

// SendPacket implements Router.
func (r *PerfectRouter) SendPacket(p Packet) error {
	conn, ok := r.nodes.Get(p.To)
	if !ok {
		return errors.New("unknown destination")
	}

	conn.RecvPacket(p)
	return nil
}

func (r *PerfectRouter) AddNode(addr net.Addr, conn PacketReceiver) {
	r.nodes.Set(addr, conn)
}

func (r *PerfectRouter) RemoveNode(addr net.Addr) {
	r.nodes.Delete(addr)
}

var _ Router = &PerfectRouter{}

type DelayedPacketReceiver struct {
	inner PacketReceiver
	delay time.Duration
}

func (r *DelayedPacketReceiver) RecvPacket(p Packet) {
	time.AfterFunc(r.delay, func() { r.inner.RecvPacket(p) })
}

type FixedLatencyRouter struct {
	PerfectRouter
	latency time.Duration
}

func (r *FixedLatencyRouter) SendPacket(p Packet) error {
	return r.PerfectRouter.SendPacket(p)
}

func (r *FixedLatencyRouter) AddNode(addr net.Addr, conn PacketReceiver) {
	r.PerfectRouter.AddNode(addr, &DelayedPacketReceiver{
		inner: conn,
		delay: r.latency,
	})
}

var _ Router = &FixedLatencyRouter{}
