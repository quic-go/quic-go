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
	AddStreamFrame(*wire.StreamFrame) error
	HasDataForWriting() bool
	GetDataForWriting(maxBytes protocol.ByteCount) (data []byte, shouldSendFin bool)
	GetWriteOffset() protocol.ByteCount
	Cancel(error)
	SetReadOffset(protocol.ByteCount)
	// methods needed for flow control
	GetWindowUpdate() protocol.ByteCount
	UpdateSendWindow(protocol.ByteCount)
	IsFlowControlBlocked() bool
}

type cryptoStream struct {
	*stream
}

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
