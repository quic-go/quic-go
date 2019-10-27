package testutils

import (
	"bytes"

	"github.com/lucas-clemente/quic-go/internal/handshake"
	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/wire"
)

// Utilities for simulating packet injection and man-in-the-middle (MITM) attacker tests.
// Do not use for non-testing purposes.

// CryptoFrameType uses same types as messageType in crypto_setup.go
type CryptoFrameType uint8

// writePacket returns a new raw packet with the specified header and payload
func writePacket(hdr *wire.ExtendedHeader, data []byte) []byte {
	buf := &bytes.Buffer{}
	hdr.Write(buf, protocol.VersionTLS)
	return append(buf.Bytes(), data...)
}

// packRawPayload returns a new raw payload containing given frames
func packRawPayload(version protocol.VersionNumber, frames []wire.Frame) []byte {
	buf := new(bytes.Buffer)
	for _, cf := range frames {
		cf.Write(buf, version)
	}
	return buf.Bytes()
}

// ComposeCryptoFrame returns a new empty crypto frame of the specified
// type padded to size bytes with zeroes
func ComposeCryptoFrame(cft CryptoFrameType, size int) *wire.CryptoFrame {
	data := make([]byte, size)
	data[0] = byte(cft)
	return &wire.CryptoFrame{
		Offset: 0,
		Data:   data,
	}
}

// ComposeConnCloseFrame returns a new Connection Close frame with a generic error
func ComposeConnCloseFrame() *wire.ConnectionCloseFrame {
	return &wire.ConnectionCloseFrame{
		IsApplicationError: true,
		ErrorCode:          0,
		ReasonPhrase:       "mitm attacker",
	}
}

// ComposeAckFrame returns a new Ack Frame that acknowledges all packets between smallest and largest
func ComposeAckFrame(smallest protocol.PacketNumber, largest protocol.PacketNumber) *wire.AckFrame {
	ackRange := wire.AckRange{
		Smallest: smallest,
		Largest:  largest,
	}
	return &wire.AckFrame{
		AckRanges: []wire.AckRange{ackRange},
		DelayTime: 0,
	}
}

// ComposeInitialPacket returns an Initial packet encrypted under key
// (the original destination connection ID) containing specified frames
func ComposeInitialPacket(srcConnID protocol.ConnectionID, destConnID protocol.ConnectionID, version protocol.VersionNumber, key protocol.ConnectionID, frames []wire.Frame) []byte {
	sealer, _ := handshake.NewInitialAEAD(key, protocol.PerspectiveServer)

	// compose payload
	var payload []byte
	if len(frames) == 0 {
		payload = make([]byte, protocol.MinInitialPacketSize)
	} else {
		payload = packRawPayload(version, frames)
	}

	// compose Initial header
	payloadSize := len(payload)
	pnLength := protocol.PacketNumberLen4
	length := payloadSize + int(pnLength) + sealer.Overhead()
	hdr := &wire.ExtendedHeader{
		Header: wire.Header{
			IsLongHeader:     true,
			Type:             protocol.PacketTypeInitial,
			SrcConnectionID:  srcConnID,
			DestConnectionID: destConnID,
			Length:           protocol.ByteCount(length),
			Version:          version,
		},
		PacketNumberLen: pnLength,
		PacketNumber:    0x0,
	}

	raw := writePacket(hdr, payload)

	// encrypt payload and header
	payloadOffset := len(raw) - payloadSize
	var encrypted []byte
	encrypted = sealer.Seal(encrypted, payload, hdr.PacketNumber, raw[:payloadOffset])
	hdrBytes := raw[0:payloadOffset]
	encrypted = append(hdrBytes, encrypted...)
	pnOffset := payloadOffset - int(pnLength) // packet number offset
	sealer.EncryptHeader(
		encrypted[payloadOffset:payloadOffset+16], // first 16 bytes of payload (sample)
		&encrypted[0],                     // first byte of header
		encrypted[pnOffset:payloadOffset], // packet number bytes
	)
	return encrypted
}

// ComposeRetryPacket returns a new raw Retry Packet
func ComposeRetryPacket(srcConnID protocol.ConnectionID, destConnID protocol.ConnectionID, origDestConnID protocol.ConnectionID, token []byte, version protocol.VersionNumber) []byte {
	hdr := &wire.ExtendedHeader{
		Header: wire.Header{
			IsLongHeader:         true,
			Type:                 protocol.PacketTypeRetry,
			SrcConnectionID:      srcConnID,
			DestConnectionID:     destConnID,
			OrigDestConnectionID: origDestConnID,
			Token:                token,
			Version:              version,
		},
	}
	return writePacket(hdr, nil)
}
