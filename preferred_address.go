package quic

import (
	"crypto/rand"
	"net"
	"net/netip"
	"slices"

	"github.com/quic-go/quic-go/internal/ackhandler"
	"github.com/quic-go/quic-go/internal/monotime"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/wire"
)

// The number of PATH_CHALLENGE frames the client is willing to send to the
// server's preferred address before it concludes that nothing is listening
// there and stays on the path it is already using.
const maxPreferredAddressProbes = 3

// preferredAddressMigration tracks the client's move to the address the server
// asked it to use (RFC 9000, section 9.6).
//
// The outgoing path manager models a change of local socket, which is the wrong
// shape here: the socket stays put and it is the peer's address that changes.
// The state machine is otherwise the same one - probe, wait for the matching
// PATH_RESPONSE, then switch - so it keeps the same shape as pathOutgoing.
//
// It is only ever touched from the connection's run loop.
type preferredAddressMigration struct {
	addr net.Addr
	// The data of every PATH_CHALLENGE sent for this migration. Retransmissions
	// use fresh data (RFC 9000, section 8.2.1), and a PATH_RESPONSE answering
	// any of them validates the path. The list is kept after validation so that
	// a duplicate PATH_RESPONSE is still recognized as ours.
	pathChallenges [][8]byte
	// Set when a PATH_CHALLENGE is waiting to be packed.
	armed bool
	// Number of PATH_CHALLENGE frames sent so far.
	attempts int
	// Set when a PATH_RESPONSE matching one of the sent probes has arrived from
	// the preferred address. The move itself is committed only after the whole
	// packet carrying it has been processed.
	responseReceived bool
	// Set once the path has been validated and the connection moved.
	done bool
	// Set when the migration has been given up on: either the probes went
	// unanswered, or the server retired the connection ID it reserved for the
	// new path.
	abandoned bool
}

// preferredAddressFor picks the offered address whose family matches the path
// the connection is already on. A client that switched families would be
// probing a path its network may not carry at all, so if the matching family
// isn't on offer it stays where it is.
func preferredAddressFor(pa *wire.PreferredAddress, current net.Addr) (net.Addr, bool) {
	udpAddr, ok := current.(*net.UDPAddr)
	if !ok {
		return nil, false
	}
	var addr netip.AddrPort
	// To4 also matches IPv4-mapped IPv6 addresses, which is what we want: the
	// datagrams on such a path are IPv4 datagrams.
	if udpAddr.IP.To4() != nil {
		addr = pa.IPv4
	} else {
		addr = pa.IPv6
	}
	if !addr.IsValid() || addr.Addr().IsUnspecified() || addr.Port() == 0 {
		return nil, false
	}
	// A link-local preferred address is only reachable through the interface
	// the current path already uses, and converting through netip drops the
	// zone that names it.
	if a := addr.Addr(); a.Is6() && a.IsLinkLocalUnicast() && udpAddr.Zone != "" {
		addr = netip.AddrPortFrom(a.WithZone(udpAddr.Zone), addr.Port())
	}
	return net.UDPAddrFromAddrPort(addr), true
}

// startPreferredAddressMigration arms the migration to the server's preferred
// address. It is called when the handshake is confirmed: before that point the
// transport parameters aren't authenticated, so probing an address taken from
// them would let an attacker aim traffic at a third party.
//
// Nothing moves yet. The address has to answer a PATH_CHALLENGE first.
func (c *Conn) startPreferredAddressMigration() {
	if c.perspective != protocol.PerspectiveClient || c.preferredAddress != nil {
		return
	}
	if c.peerParams == nil || c.peerParams.PreferredAddress == nil {
		return
	}
	addr, ok := preferredAddressFor(c.peerParams.PreferredAddress, c.conn.RemoteAddr())
	if !ok {
		// The offer is unusable, but the connection ID that came with it still
		// holds sequence number 1 and the server may not issue that number
		// again. Keeping it reserved is what stops a later NEW_CONNECTION_ID
		// for the same sequence number being taken as an ordinary addition.
		return
	}
	c.preferredAddress = &preferredAddressMigration{addr: addr, armed: true}
	c.scheduleSending()
}

// sendPreferredAddressProbe packs and sends a PATH_CHALLENGE to the preferred
// address. It reports whether a packet was written.
//
// The probe is sent from the socket the connection is already using, addressed
// to the preferred address, and it carries the connection ID the server
// reserved for that path.
func (c *Conn) sendPreferredAddressProbe(now monotime.Time) (bool, error) {
	m := c.preferredAddress
	if m == nil || !m.armed || m.done || m.abandoned {
		return false, nil
	}
	// The connection ID is looked up again for every probe rather than
	// remembered: the server can retire it at any point, and a retired
	// connection ID must not appear on the wire again (RFC 9000, section 5.1.2).
	connID, ok := c.connIDManager.PreferredAddressConnID()
	if !ok {
		c.abandonPreferredAddressMigration()
		return false, nil
	}
	var data [8]byte
	if _, err := rand.Read(data[:]); err != nil {
		return false, err
	}
	frame := ackhandler.Frame{
		Frame:   &wire.PathChallengeFrame{Data: data},
		Handler: (*preferredAddressProbeHandler)(c),
	}
	probe, buf, err := c.packer.PackPathProbePacket(connID, []ackhandler.Frame{frame}, c.version)
	if err != nil {
		return false, err
	}
	m.pathChallenges = append(m.pathChallenges, data)
	m.armed = false
	m.attempts++
	c.logger.Debugf("sending path probe packet to preferred address %s", m.addr)
	c.logShortHeaderPacket(probe, protocol.ECNNon, buf.Len())
	c.registerPackedShortHeaderPacket(probe, protocol.ECNNon, now)
	c.sendQueue.SendProbe(buf, m.addr, packetInfo{})
	// The connection ID is on the wire now, and the stateless reset token that
	// came with it takes effect with it - the same moment the ordinary path
	// probing machinery registers its tokens.
	c.connIDManager.RegisterPreferredAddressResetToken()
	return true, nil
}

// handlePreferredAddressResponse completes the migration when the probe is
// answered. It reports whether the frame belonged to this migration, so that
// the caller knows to stop looking for an outgoing path it matches.
//
// A PATH_RESPONSE that repeats one already seen is ours as well: the peer is
// allowed to send it, so it is accepted and ignored rather than treated as a
// frame nobody asked for.
func (c *Conn) handlePreferredAddressResponse(f *wire.PathResponseFrame, from net.Addr) bool {
	m := c.preferredAddress
	if m == nil || !slices.Contains(m.pathChallenges, f.Data) {
		return false
	}
	// From here on the frame is ours: it answers a PATH_CHALLENGE this
	// connection really sent. Whatever else is wrong with it, it may not fall
	// through to the generic handler - PROTOCOL_VIOLATION is only for a
	// PATH_RESPONSE whose content does not match any PATH_CHALLENGE previously sent
	// (RFC 9000, section 19.18), and closing a working connection over a frame
	// we solicited is worse than ignoring it.
	if m.done || m.abandoned {
		return true
	}
	// The answer has to come back from the path being validated. A response
	// carrying the right data but arriving elsewhere demonstrates nothing about
	// whether the preferred address is reachable - a server bound to a wildcard
	// socket routinely answers from its primary source address - so it is
	// consumed without validating the path, and the probe keeps waiting.
	if !addrUsable(from) || !addrsEqual(from, m.addr) {
		return true
	}
	// Record only. The rest of this packet has not been parsed yet, and a later
	// frame in it may retire the connection ID this move depends on - "before
	// the connection has moved" includes the frames sharing the response's own
	// packet. The caller commits once the whole packet has been processed, the
	// same way a PATH_CHALLENGE is carried out of frame parsing and answered
	// afterwards.
	m.responseReceived = true
	return true
}

// commitPreferredAddressMove completes a migration whose probe was answered,
// once every frame of the packet carrying the answer has been processed. If a
// frame later in that packet retired the reserved connection ID, there is
// nothing left to move with and the connection stays where it is.
func (c *Conn) commitPreferredAddressMove(now monotime.Time) {
	m := c.preferredAddress
	if m == nil || m.done || m.abandoned || !m.responseReceived {
		return
	}
	m.armed = false
	if !c.connIDManager.UsePreferredAddressConnID() {
		// A frame later in the same packet retired the reserved connection ID:
		// there is nothing to move with, so this is an abandonment, not a move.
		m.abandoned = true
		return
	}
	m.done = true
	initialPacketSize := protocol.ByteCount(c.config.InitialPacketSize)
	// The new path has a congestion window and an MTU of its own; nothing
	// learned about the old one carries over.
	c.sentPacketHandler.MigratedPath(now, initialPacketSize)
	maxPacketSize := protocol.ByteCount(protocol.MaxPacketBufferSize)
	if c.peerParams.MaxUDPPayloadSize > 0 && c.peerParams.MaxUDPPayloadSize < maxPacketSize {
		maxPacketSize = c.peerParams.MaxUDPPayloadSize
	}
	c.mtuDiscoverer.Reset(now, initialPacketSize, maxPacketSize)
	// Packets already handed to the send queue were packed with the old path's
	// connection ID and addressed to the old path. A packet is not on the
	// network when it is queued, and the send connection is read at write time,
	// so redirecting the connection in place would send them to the preferred
	// address under the wrong connection ID - and draining them where they were
	// headed would keep using an address the connection has left. Drop them
	// instead: to the peer that is ordinary loss, and loss recovery repacks
	// their frames for the new path.
	if sc, ok := c.conn.(*sconn); ok {
		c.conn = newSendConn(sc.rawConn, m.addr, packetInfo{}, sc.logger)
		c.sendQueue.CloseAndDiscard()
		c.sendQueue = newSendQueue(c.conn)
		go func() {
			if err := c.sendQueue.Run(); err != nil {
				c.destroyImpl(err)
			}
		}()
	} else {
		// A send connection this package did not build cannot be rebuilt
		// around its socket; redirecting it is all that is left.
		c.conn.ChangeRemoteAddr(m.addr, packetInfo{})
	}
	c.scheduleSending()
}

// abandonPreferredAddressMigration gives up on the move and leaves the
// connection on the path it is already using. The connection ID that was
// reserved for the new path is handed back, since it will never be used.
func (c *Conn) abandonPreferredAddressMigration() {
	m := c.preferredAddress
	if m == nil || m.done || m.abandoned {
		return
	}
	m.abandoned = true
	m.armed = false
	// The pathChallenges list stays on the record. It is what tells a late
	// response apart from one nobody asked for.
	c.logger.Debugf("giving up on the preferred address %s", m.addr)
	c.connIDManager.RetirePreferredAddressConnID()
}

// preferredAddressProbeLost re-arms the probe when a PATH_CHALLENGE is declared
// lost. After maxPreferredAddressProbes attempts the address is treated as
// unreachable.
func (c *Conn) preferredAddressProbeLost(data [8]byte) {
	m := c.preferredAddress
	if m == nil || m.done || m.abandoned || !slices.Contains(m.pathChallenges, data) {
		return
	}
	if m.attempts >= maxPreferredAddressProbes {
		c.abandonPreferredAddressMigration()
		return
	}
	m.armed = true
	c.scheduleSending()
}

// preferredAddressProbeHandler is notified about the fate of the packets
// carrying the PATH_CHALLENGE frames sent to the preferred address.
type preferredAddressProbeHandler Conn

var _ ackhandler.FrameHandler = (*preferredAddressProbeHandler)(nil)

// OnAcked is called when the packet carrying the PATH_CHALLENGE is
// acknowledged. That says nothing about the new path: the acknowledgement comes
// back on the old one. Only the PATH_RESPONSE validates the path.
func (h *preferredAddressProbeHandler) OnAcked(wire.Frame) {}

func (h *preferredAddressProbeHandler) OnLost(f wire.Frame) {
	pc, ok := f.(*wire.PathChallengeFrame)
	if !ok {
		return
	}
	(*Conn)(h).preferredAddressProbeLost(pc.Data)
}

// addrUsable reports whether an address can be compared. A *net.UDPAddr can be
// nil inside a non-nil net.Addr, which survives an ordinary nil check and then
// panics on the first field access; the test connections in this package hand
// exactly that shape to client packets.
func addrUsable(a net.Addr) bool {
	if a == nil {
		return false
	}
	if u, ok := a.(*net.UDPAddr); ok && u == nil {
		return false
	}
	return true
}
