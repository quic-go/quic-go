package h2quic

import (
	"fmt"

	"github.com/lucas-clemente/quic-go/protocol"
	"golang.org/x/net/http2"
)

const frameHeaderLen = 4

// PushPromiseFrame constructs a HTTP2/QUIC push promise frame
// BlockFragment is part (or all) of a Header Block.
func PushPromiseFrame(promiseID protocol.StreamID, blockFragment []byte) ([]byte, error) {
	if promiseID == 0 {
		return nil, fmt.Errorf("Invalid streamID: %x", promiseID)
	}
	buffer, err := startWrite(http2.FramePushPromise, http2.FlagHeadersEndHeaders, len(blockFragment)+4)
	if err != nil {
		return nil, err
	}
	// TODO: check padLength, endHeaders, padding. See http2/frame.go:WritePushPromise(p PushPromiseParam)
	buffer = append(buffer,
		byte(promiseID<<24),
		byte(promiseID<<16),
		byte(promiseID<<8),
		byte(promiseID),
	)
	buffer = append(buffer, blockFragment...)
	err = endWrite(&buffer)
	if err != nil {
		return nil, err
	}
	return buffer, nil
}

// Writes the fixed start of the header
func startWrite(frameType http2.FrameType, flags http2.Flags, payloadSize int) ([]byte, error) {
	if payloadSize < 0 || payloadSize >= (1<<16) {
		return nil, fmt.Errorf("Invalid payload size: %d", payloadSize)
	}
	buffer := make([]byte, frameHeaderLen, payloadSize+frameHeaderLen)
	buffer[2] = byte(frameType)
	buffer[3] = byte(flags)
	return buffer, nil
}

// Fills in the length
func endWrite(buffer *[]byte) error {
	length := len(*buffer) - frameHeaderLen
	if length >= (1 << 16) {
		return fmt.Errorf("Frame larger than 2^16: %d", length)
	}
	(*buffer)[0] = byte(length >> 8)
	(*buffer)[1] = byte(length)
	return nil
}
