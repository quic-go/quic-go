package quicproxy

import (
	"net"
	"sort"
	"sync"
	"time"

	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/utils"
)

// Connection is a UDP connection
type connection struct {
	ClientAddr *net.UDPAddr // Address of the client
	ServerConn *net.UDPConn // UDP connection to server

	incomingPackets chan packetEntry

	Incoming *queue
	Outgoing *queue
}

func (c *connection) queuePacket(t time.Time, b []byte) {
	c.incomingPackets <- packetEntry{Time: t, Raw: b}
}

// Direction is the direction a packet is sent.
type Direction int

const (
	// DirectionIncoming is the direction from the client to the server.
	DirectionIncoming Direction = iota
	// DirectionOutgoing is the direction from the server to the client.
	DirectionOutgoing
	// DirectionBoth is both incoming and outgoing
	DirectionBoth
)

type packetEntry struct {
	Time time.Time
	Raw  []byte
}

type packetEntries []packetEntry

func (e packetEntries) Len() int           { return len(e) }
func (e packetEntries) Less(i, j int) bool { return e[i].Time.Before(e[j].Time) }
func (e packetEntries) Swap(i, j int)      { e[i], e[j] = e[j], e[i] }

type queue struct {
	sync.Mutex

	timer   *utils.Timer
	Packets packetEntries
}

func newQueue() *queue {
	return &queue{timer: utils.NewTimer()}
}

func (q *queue) Add(e packetEntry) {
	q.Lock()
	q.Packets = append(q.Packets, e)
	if len(q.Packets) > 1 {
		lastIndex := len(q.Packets) - 1
		if q.Packets[lastIndex].Time.Before(q.Packets[lastIndex-1].Time) {
			sort.Stable(q.Packets)
		}
	}
	q.timer.Reset(q.Packets[0].Time)
	q.Unlock()
}

func (q *queue) Get() []byte {
	q.Lock()
	raw := q.Packets[0].Raw
	q.Packets = q.Packets[1:]
	if len(q.Packets) > 0 {
		q.timer.Reset(q.Packets[0].Time)
	}
	q.Unlock()
	return raw
}

func (q *queue) Timer() <-chan time.Time { return q.timer.Chan() }
func (q *queue) SetTimerRead()           { q.timer.SetRead() }

func (q *queue) Close() { q.timer.Stop() }

func (d Direction) String() string {
	switch d {
	case DirectionIncoming:
		return "Incoming"
	case DirectionOutgoing:
		return "Outgoing"
	case DirectionBoth:
		return "both"
	default:
		panic("unknown direction")
	}
}

// Is says if one direction matches another direction.
// For example, incoming matches both incoming and both, but not outgoing.
func (d Direction) Is(dir Direction) bool {
	if d == DirectionBoth || dir == DirectionBoth {
		return true
	}
	return d == dir
}

// DropCallback is a callback that determines which packet gets dropped.
type DropCallback func(dir Direction, packet []byte) bool

// NoDropper doesn't drop packets.
var NoDropper DropCallback = func(Direction, []byte) bool {
	return false
}

// DelayCallback is a callback that determines how much delay to apply to a packet.
type DelayCallback func(dir Direction, packet []byte) time.Duration

// NoDelay doesn't apply a delay.
var NoDelay DelayCallback = func(Direction, []byte) time.Duration {
	return 0
}

// Opts are proxy options.
type Opts struct {
	// The address this proxy proxies packets to.
	RemoteAddr string
	// DropPacket determines whether a packet gets dropped.
	DropPacket DropCallback
	// DelayPacket determines how long a packet gets delayed. This allows
	// simulating a connection with non-zero RTTs.
	// Note that the RTT is the sum of the delay for the incoming and the outgoing packet.
	DelayPacket DelayCallback
}

// QuicProxy is a QUIC proxy that can drop and delay packets.
type QuicProxy struct {
	mutex sync.Mutex

	closeChan chan struct{}

	conn       *net.UDPConn
	serverAddr *net.UDPAddr

	dropPacket  DropCallback
	delayPacket DelayCallback

	// Mapping from client addresses (as host:port) to connection
	clientDict map[string]*connection

	logger utils.Logger
}

// NewQuicProxy creates a new UDP proxy
func NewQuicProxy(local string, opts *Opts) (*QuicProxy, error) {
	if opts == nil {
		opts = &Opts{}
	}
	laddr, err := net.ResolveUDPAddr("udp", local)
	if err != nil {
		return nil, err
	}
	conn, err := net.ListenUDP("udp", laddr)
	if err != nil {
		return nil, err
	}
	raddr, err := net.ResolveUDPAddr("udp", opts.RemoteAddr)
	if err != nil {
		return nil, err
	}

	packetDropper := NoDropper
	if opts.DropPacket != nil {
		packetDropper = opts.DropPacket
	}

	packetDelayer := NoDelay
	if opts.DelayPacket != nil {
		packetDelayer = opts.DelayPacket
	}

	p := QuicProxy{
		clientDict:  make(map[string]*connection),
		conn:        conn,
		closeChan:   make(chan struct{}),
		serverAddr:  raddr,
		dropPacket:  packetDropper,
		delayPacket: packetDelayer,
		logger:      utils.DefaultLogger.WithPrefix("proxy"),
	}

	p.logger.Debugf("Starting UDP Proxy %s <-> %s", conn.LocalAddr(), raddr)
	go p.runProxy()
	return &p, nil
}

// Close stops the UDP Proxy
func (p *QuicProxy) Close() error {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	close(p.closeChan)
	for _, c := range p.clientDict {
		if err := c.ServerConn.Close(); err != nil {
			return err
		}
		c.Incoming.Close()
		c.Outgoing.Close()
	}
	return p.conn.Close()
}

// LocalAddr is the address the proxy is listening on.
func (p *QuicProxy) LocalAddr() net.Addr {
	return p.conn.LocalAddr()
}

// LocalPort is the UDP port number the proxy is listening on.
func (p *QuicProxy) LocalPort() int {
	return p.conn.LocalAddr().(*net.UDPAddr).Port
}

func (p *QuicProxy) newConnection(cliAddr *net.UDPAddr) (*connection, error) {
	srvudp, err := net.DialUDP("udp", nil, p.serverAddr)
	if err != nil {
		return nil, err
	}
	return &connection{
		ClientAddr:      cliAddr,
		ServerConn:      srvudp,
		incomingPackets: make(chan packetEntry, 10),
		Incoming:        newQueue(),
		Outgoing:        newQueue(),
	}, nil
}

// runProxy listens on the proxy address and handles incoming packets.
func (p *QuicProxy) runProxy() error {
	for {
		buffer := make([]byte, protocol.MaxPacketBufferSize)
		n, cliaddr, err := p.conn.ReadFromUDP(buffer)
		if err != nil {
			return err
		}
		raw := buffer[0:n]

		saddr := cliaddr.String()
		p.mutex.Lock()
		conn, ok := p.clientDict[saddr]

		if !ok {
			conn, err = p.newConnection(cliaddr)
			if err != nil {
				p.mutex.Unlock()
				return err
			}
			p.clientDict[saddr] = conn
			go p.runIncomingConnection(conn)
			go p.runOutgoingConnection(conn)
		}
		p.mutex.Unlock()

		if p.dropPacket(DirectionIncoming, raw) {
			if p.logger.Debug() {
				p.logger.Debugf("dropping incoming packet(%d bytes)", n)
			}
			continue
		}

		delay := p.delayPacket(DirectionIncoming, raw)
		if delay == 0 {
			if p.logger.Debug() {
				p.logger.Debugf("forwarding incoming packet (%d bytes) to %s", len(raw), conn.ServerConn.RemoteAddr())
			}
			if _, err := conn.ServerConn.Write(raw); err != nil {
				return err
			}
		} else {
			now := time.Now()
			if p.logger.Debug() {
				p.logger.Debugf("delaying incoming packet (%d bytes) to %s by %s", len(raw), conn.ServerConn.RemoteAddr(), delay)
			}
			conn.queuePacket(now.Add(delay), raw)
		}
	}
}

// runConnection handles packets from server to a single client
func (p *QuicProxy) runOutgoingConnection(conn *connection) error {
	outgoingPackets := make(chan packetEntry, 10)
	go func() {
		for {
			buffer := make([]byte, protocol.MaxPacketBufferSize)
			n, err := conn.ServerConn.Read(buffer)
			if err != nil {
				return
			}
			raw := buffer[0:n]

			if p.dropPacket(DirectionOutgoing, raw) {
				if p.logger.Debug() {
					p.logger.Debugf("dropping outgoing packet(%d bytes)", n)
				}
				continue
			}

			delay := p.delayPacket(DirectionOutgoing, raw)
			if delay == 0 {
				if p.logger.Debug() {
					p.logger.Debugf("forwarding outgoing packet (%d bytes) to %s", len(raw), conn.ClientAddr)
				}
				if _, err := p.conn.WriteToUDP(raw, conn.ClientAddr); err != nil {
					return
				}
			} else {
				now := time.Now()
				if p.logger.Debug() {
					p.logger.Debugf("delaying outgoing packet (%d bytes) to %s by %s", len(raw), conn.ClientAddr, delay)
				}
				outgoingPackets <- packetEntry{Time: now.Add(delay), Raw: raw}
			}
		}
	}()

	for {
		select {
		case <-p.closeChan:
			return nil
		case e := <-outgoingPackets:
			conn.Outgoing.Add(e)
		case <-conn.Outgoing.Timer():
			conn.Outgoing.SetTimerRead()
			if _, err := p.conn.WriteTo(conn.Outgoing.Get(), conn.ClientAddr); err != nil {
				return err
			}
		}
	}
}

func (p *QuicProxy) runIncomingConnection(conn *connection) error {
	for {
		select {
		case <-p.closeChan:
			return nil
		case e := <-conn.incomingPackets:
			// Send the packet to the server
			conn.Incoming.Add(e)
		case <-conn.Incoming.Timer():
			conn.Incoming.SetTimerRead()
			if _, err := conn.ServerConn.Write(conn.Incoming.Get()); err != nil {
				return err
			}
		}
	}
}
