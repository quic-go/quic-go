package quic

import (
	"sync"

	"github.com/lucas-clemente/quic-go/internal/protocol"
)

type packetBuffer struct {
	Slice []byte

	// refCount counts how many packets the Slice is used in.
	// It doesn't support concurrent use.
	// It is > 1 when used for coalesced packet.
	refCount int
}

var bufferPool sync.Pool

func getPacketBuffer() *packetBuffer {
	buf := bufferPool.Get().(*packetBuffer)
	buf.refCount = 1
	buf.Slice = buf.Slice[:protocol.MaxReceivePacketSize]
	return buf
}

func putPacketBuffer(buf *packetBuffer) {
	if cap(buf.Slice) != int(protocol.MaxReceivePacketSize) {
		panic("putPacketBuffer called with packet of wrong size!")
	}
	buf.refCount--
	if buf.refCount < 0 {
		panic("negative packetBuffer refCount")
	}
	// only put the packetBuffer back if it's not used any more
	if buf.refCount == 0 {
		bufferPool.Put(buf)
	}
}

func init() {
	bufferPool.New = func() interface{} {
		return &packetBuffer{
			Slice: make([]byte, 0, protocol.MaxReceivePacketSize),
		}
	}
}
