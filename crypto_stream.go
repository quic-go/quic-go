package quic

import (
	"io"

	"github.com/lucas-clemente/quic-go/internal/flowcontrol"
	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/wire"
)

type cryptoStreamI interface {
	io.Reader
	io.Writer
	HandleStreamFrame(*wire.StreamFrame) error
	PopStreamFrame(protocol.ByteCount) *wire.StreamFrame
	CloseForShutdown(error)
	HasDataForWriting() bool
	SetReadOffset(protocol.ByteCount)
	// methods needed for flow control
	GetWindowUpdate() protocol.ByteCount
	HandleMaxStreamDataFrame(*wire.MaxStreamDataFrame)
	IsFlowControlBlocked() (bool, protocol.ByteCount)
}

type cryptoStream struct {
	*stream
}

var _ cryptoStreamI = &cryptoStream{}

func newCryptoStream(onData func(), flowController flowcontrol.StreamFlowController, version protocol.VersionNumber) cryptoStreamI {
	str := newStream(version.CryptoStreamID(), onData, nil, flowController, version)
	return &cryptoStream{str}
}

// SetReadOffset sets the read offset.
// It is only needed for the crypto stream.
// It must not be called concurrently with any other stream methods, especially Read and Write.
func (s *cryptoStream) SetReadOffset(offset protocol.ByteCount) {
	s.readOffset = offset
	s.frameQueue.readPosition = offset
}

func (s *cryptoStream) HasDataForWriting() bool {
	s.mutex.Lock()
	hasData := s.dataForWriting != nil
	s.mutex.Unlock()
	return hasData
}
