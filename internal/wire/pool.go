package wire

import (
	"sync"

	"github.com/quic-go/quic-go/internal/protocol"
)

// STREAM frames are pooled in two buffer sizes:
// protocol.MaxPacketBufferSize for frames that fit into a QUIC packet,
// and protocol.MaxLargePacketBufferSize for the larger frames permitted in QMux records.
var pool, largePool sync.Pool

func init() {
	pool.New = func() any {
		return &StreamFrame{
			Data:     make([]byte, 0, protocol.MaxPacketBufferSize),
			fromPool: true,
		}
	}
	largePool.New = func() any {
		return &StreamFrame{
			Data:     make([]byte, 0, protocol.MaxLargePacketBufferSize),
			fromPool: true,
		}
	}
}

// GetStreamFrame gets a StreamFrame whose Data buffer has a capacity of at least size bytes.
func GetStreamFrame(size protocol.ByteCount) *StreamFrame {
	switch {
	case size <= protocol.MaxPacketBufferSize:
		return pool.Get().(*StreamFrame)
	case size <= protocol.MaxLargePacketBufferSize:
		return largePool.Get().(*StreamFrame)
	default:
		// This should never happen: frames are limited by the packet / record size.
		return &StreamFrame{Data: make([]byte, 0, size)}
	}
}

func putStreamFrame(f *StreamFrame) {
	if !f.fromPool {
		return
	}
	switch protocol.ByteCount(cap(f.Data)) {
	case protocol.MaxPacketBufferSize:
		pool.Put(f)
	case protocol.MaxLargePacketBufferSize:
		largePool.Put(f)
	default:
		panic("wire.PutStreamFrame called with packet of wrong size!")
	}
}
