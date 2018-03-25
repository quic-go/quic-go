package quic

import (
	"bytes"

	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/wire"
	"github.com/lucas-clemente/quic-go/qerr"
)

type unpackedPacket struct {
	encryptionLevel protocol.EncryptionLevel
	frames          []wire.Frame
}

type quicAEAD interface {
	Open(dst, src []byte, packetNumber protocol.PacketNumber, associatedData []byte) ([]byte, protocol.EncryptionLevel, error)
}

type packetUnpacker struct {
	version protocol.VersionNumber
	aead    quicAEAD
}

func (u *packetUnpacker) Unpack(headerBinary []byte, hdr *wire.Header, data []byte) (*unpackedPacket, error) {
	buf := *getPacketBuffer()
	buf = buf[:0]
	defer putPacketBuffer(&buf)
	decrypted, encryptionLevel, err := u.aead.Open(buf, data, hdr.PacketNumber, headerBinary)
	if err != nil {
		// Wrap err in quicError so that public reset is sent by session
		return nil, qerr.Error(qerr.DecryptionFailure, err.Error())
	}
	r := bytes.NewReader(decrypted)

	if r.Len() == 0 {
		return nil, qerr.MissingPayload
	}

	fs := make([]wire.Frame, 0, 2)

	// Read all frames in the packet
	for {
		frame, err := wire.ParseNextFrame(r, hdr, u.version)
		if err != nil {
			return nil, err
		}
		if frame == nil {
			break
		}
		fs = append(fs, frame)
	}

	return &unpackedPacket{
		encryptionLevel: encryptionLevel,
		frames:          fs,
	}, nil
}
