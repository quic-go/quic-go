package quic

import (
	"fmt"
	"io"

	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/utils"
	"github.com/lucas-clemente/quic-go/internal/wire"
)

type cryptoStream interface {
	// for receiving data
	HandleCryptoFrame(*wire.CryptoFrame) error
	GetCryptoData() []byte
	// for sending data
	io.Writer
	HasData() bool
	PopCryptoFrame(protocol.ByteCount) *wire.CryptoFrame
}

type cryptoStreamImpl struct {
	queue *frameSorter

	writeOffset protocol.ByteCount
	writeBuf    []byte
}

func newCryptoStream() cryptoStream {
	return &cryptoStreamImpl{
		queue: newFrameSorter(),
	}
}

func (s *cryptoStreamImpl) HandleCryptoFrame(f *wire.CryptoFrame) error {
	if maxOffset := f.Offset + protocol.ByteCount(len(f.Data)); maxOffset > protocol.MaxCryptoStreamOffset {
		return fmt.Errorf("received invalid offset %d on crypto stream, maximum allowed %d", maxOffset, protocol.MaxCryptoStreamOffset)
	}
	return s.queue.Push(f.Data, f.Offset, false)
}

// GetCryptoData retrieves data that was received in CRYPTO frames
func (s *cryptoStreamImpl) GetCryptoData() []byte {
	data, _ := s.queue.Pop()
	return data
}

// Writes writes data that should be sent out in CRYPTO frames
func (s *cryptoStreamImpl) Write(p []byte) (int, error) {
	s.writeBuf = append(s.writeBuf, p...)
	return len(p), nil
}

func (s *cryptoStreamImpl) HasData() bool {
	return len(s.writeBuf) > 0
}

func (s *cryptoStreamImpl) PopCryptoFrame(maxLen protocol.ByteCount) *wire.CryptoFrame {
	f := &wire.CryptoFrame{Offset: s.writeOffset}
	n := utils.MinByteCount(f.MaxDataLen(maxLen), protocol.ByteCount(len(s.writeBuf)))
	f.Data = s.writeBuf[:n]
	s.writeBuf = s.writeBuf[n:]
	s.writeOffset += n
	return f
}
