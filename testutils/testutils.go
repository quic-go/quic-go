// Package testutils contains utilities for simulating packet injection and man-in-the-middle (MITM) attacker tests.
// It is not supposed to be used for non-testing purposes.
// The API is not guaranteed to be stable.
package testutils

import (
	"fmt"

	"github.com/quic-go/quic-go/internal/handshake"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/wire"
)

// writePacket returns a new raw packet with the specified header and payload
func writePacket(hdr *wire.ExtendedHeader, data []byte) []byte {
	b, err := hdr.Append(nil, hdr.Version)
	if err != nil {
		panic(fmt.Sprintf("failed to write header: %s", err))
	}
	return append(b, data...)
}

// packRawPayload returns a new raw payload containing given frames
func packRawPayload(version protocol.Version, frames []wire.Frame) []byte {
	var b []byte
	for _, cf := range frames {
		var err error
		b, err = cf.Append(b, version)
		if err != nil {
			panic(err)
		}
	}
	return b
}

// ComposeInitialPacket returns an Initial packet encrypted under key (the original destination connection ID)
// containing specified frames.
func ComposeInitialPacket(
	srcConnID, destConnID, key protocol.ConnectionID,
	token []byte,
	frames []wire.Frame,
	sentBy protocol.Perspective,
	version protocol.Version,
) []byte {
	sealer, _ := handshake.NewInitialAEAD(key, sentBy, version)

	// compose payload
	var payload []byte
	if len(frames) == 0 {
		payload = make([]byte, protocol.MinInitialPacketSize)
	} else {
		payload = packRawPayload(version, frames)
	}

	// compose Initial header
	payloadSize := len(payload)
	const pnLength = protocol.PacketNumberLen4
	length := payloadSize + int(pnLength) + sealer.Overhead()
	hdr := &wire.ExtendedHeader{
		Header: wire.Header{
			Type:             protocol.PacketTypeInitial,
			Token:            token,
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
func ComposeRetryPacket(
	srcConnID protocol.ConnectionID,
	destConnID protocol.ConnectionID,
	origDestConnID protocol.ConnectionID,
	token []byte,
	version protocol.Version,
) []byte {
	hdr := &wire.ExtendedHeader{
		Header: wire.Header{
			Type:             protocol.PacketTypeRetry,
			SrcConnectionID:  srcConnID,
			DestConnectionID: destConnID,
			Token:            token,
			Version:          version,
		},
	}
	data := writePacket(hdr, nil)
	return append(data, handshake.GetRetryIntegrityTag(data, origDestConnID, version)[:]...)
}
