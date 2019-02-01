package utils

import (
	"fmt"

	"github.com/lucas-clemente/quic-go/internal/protocol"
)

// Wrapper around T used to mark whether the entry is actually in the map.
type entryWrapper struct {
	present bool
	T       interface{}
}

func newEntryWrapper(t interface{}) *entryWrapper {
	return &entryWrapper{
		T:       t,
		present: true,
	}
}

func defaultNewEntryWrapper() *entryWrapper {
	return &entryWrapper{
		present: false,
	}
}

type PacketNumberIndexedQueue struct {
	entries                []entryWrapper
	numberOfPresentEntries int
	firstPacket            protocol.PacketNumber
}

func NewPacketNumberIndexedQueue() *PacketNumberIndexedQueue {
	return &PacketNumberIndexedQueue{
		numberOfPresentEntries: 0,
		entries:                []entryWrapper{},
	}
}

func (p *PacketNumberIndexedQueue) IsEmpty() bool {
	return p.numberOfPresentEntries == 0
}

func (p *PacketNumberIndexedQueue) GetEntryWrapper(packetNumber protocol.PacketNumber) *entryWrapper {
	if packetNumber == 0 || p.IsEmpty() ||
		packetNumber < p.firstPacket {
		return nil
	}

	var offset = int(packetNumber - p.firstPacket)
	if offset >= len(p.entries) {
		return nil
	}

	var entry = &p.entries[offset]
	if !entry.present {
		return nil
	}

	return entry
}

// Retrieve the entry associated with the packet number.  Returns the pointer
// to the entry in case of success, or nullptr if the entry does not exist.
func (p *PacketNumberIndexedQueue) GetEntry(packetNumber protocol.PacketNumber) interface{} {
	var entry = p.GetEntryWrapper(packetNumber)
	if entry == nil {
		return nil
	}
	return entry.T
}

// Inserts data associated |packet_number| into (or past) the end of the
// queue, filling up the missing intermediate entries as necessary.  Returns
// true if the element has been inserted successfully, false if it was already
// in the queue or inserted out of order.
func (p *PacketNumberIndexedQueue) Emplace(
	packetNumber protocol.PacketNumber, t interface{},
) bool {
	if packetNumber == 0 {
		fmt.Println("Try to insert an uninitialized packet number")
		return false
	}

	if p.IsEmpty() {
		//DCHECK(len(p.entries)==0)
		//DCHECK(p.firstPacket==0)

		p.entries = append(p.entries, *newEntryWrapper(t))
		p.numberOfPresentEntries = 1
		p.firstPacket = packetNumber
		return true
	}
	// Do not allow insertion out-of-order.
	if packetNumber <= p.LastPacket() {
		return false
	}

	// Handle potentially missing elements.
	var offset = packetNumber - p.firstPacket
	if int(offset) > len(p.entries) {
		entries := make([]entryWrapper, 0, offset)
		copy(entries, p.entries)
		p.entries = entries
		//p.entries.resize(offset)
	}

	p.numberOfPresentEntries++
	p.entries = append(p.entries, *newEntryWrapper(t))
	//DCHECK_EQ(packetNumber, p.LastPacket());
	return true
}

// Removes data associated with |packet_number| and frees the slots in the
// queue as necessary.
func (p *PacketNumberIndexedQueue) Remove(
	packetNumber protocol.PacketNumber) bool {
	var entry *entryWrapper = p.GetEntryWrapper(packetNumber)
	if entry == nil {
		return false
	}
	entry.present = false
	p.numberOfPresentEntries--

	if packetNumber == p.FirstPacket() {
		p.Cleanup()
	}
	return true
}

// Returns the number of entries allocated in the underlying deque.  This is
// proportional to the memory usage of the queue.
func (p *PacketNumberIndexedQueue) EntrySlotsUsed() int { return len(p.entries) }

// Packet number of the first entry in the queue.
func (p *PacketNumberIndexedQueue) FirstPacket() protocol.PacketNumber { return p.firstPacket }

// Packet number of the last entry ever inserted in the queue.  Note that the
// entry in question may have already been removed.  Zero if the queue is
// empty.
func (p *PacketNumberIndexedQueue) LastPacket() protocol.PacketNumber {
	if p.IsEmpty() {
		return protocol.PacketNumber(0)
	}
	return p.firstPacket + protocol.PacketNumber(len(p.entries)-1)
}

// Cleans up unused slots in the front after removing an element.
func (p *PacketNumberIndexedQueue) Cleanup() {
	for (len(p.entries) != 0) && !p.entries[0].present {
		p.entries = p.entries[1:]
		p.firstPacket++
	}
	if len(p.entries) == 0 {
		p.firstPacket = 0
	}
}
