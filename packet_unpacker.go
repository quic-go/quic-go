package quic

import (
	"bytes"
	"errors"
	"fmt"
	"io/ioutil"

	"github.com/lucas-clemente/quic-go/crypto"
	"github.com/lucas-clemente/quic-go/errorcodes"
	"github.com/lucas-clemente/quic-go/frames"
	"github.com/lucas-clemente/quic-go/protocol"
)

type unpackedPacket struct {
	entropyBit bool
	frames     []frames.Frame
}

type packetUnpacker struct {
	aead crypto.AEAD
}

func (u *packetUnpacker) Unpack(publicHeaderBinary []byte, publicHeader *PublicHeader, r *bytes.Reader) (*unpackedPacket, error) {
	ciphertext, _ := ioutil.ReadAll(r)
	plaintext, err := u.aead.Open(publicHeader.PacketNumber, publicHeaderBinary, ciphertext)
	if err != nil {
		return nil, err
	}
	r = bytes.NewReader(plaintext)

	privateFlag, err := r.ReadByte()
	if err != nil {
		return nil, err
	}
	entropyBit := privateFlag&0x01 > 0

	fs := []frames.Frame{}

	// Read all frames in the packet
ReadLoop:
	for r.Len() > 0 {
		typeByte, _ := r.ReadByte()
		r.UnreadByte()

		var frame frames.Frame
		if typeByte&0x80 == 0x80 {
			frame, err = frames.ParseStreamFrame(r)
		} else if typeByte&0xc0 == 0x40 {
			frame, err = frames.ParseAckFrame(r)
		} else if typeByte&0xe0 == 0x20 {
			err = errors.New("unimplemented: CONGESTION_FEEDBACK")
		} else {
			switch typeByte {
			case 0x0: // PAD, end of frames
				break ReadLoop
			case 0x01:
				frame, err = frames.ParseRstStreamFrame(r)
			case 0x02:
				frame, err = frames.ParseConnectionCloseFrame(r)
			case 0x03:
				err = errors.New("unimplemented: GOAWAY")
			case 0x04:
				frame, err = frames.ParseWindowUpdateFrame(r)
			case 0x05:
				fmt.Println("unimplemented: BLOCKED")
				p := make([]byte, 1+4)
				_, err = r.Read(p)
				frame = nil
			case 0x06:
				frame, err = frames.ParseStopWaitingFrame(r, publicHeader.PacketNumberLen)
			case 0x07:
				// PING, do nothing
				r.ReadByte()
				continue
			default:
				err = protocol.NewQuicError(errorcodes.QUIC_INVALID_FRAME_DATA, fmt.Sprintf("unknown type byte 0x%x", typeByte))
			}
		}
		if err != nil {
			return nil, err
		}
		// TODO: Remove once all frames are implemented
		if frame != nil {
			fs = append(fs, frame)
		}
	}

	return &unpackedPacket{
		entropyBit: entropyBit,
		frames:     fs,
	}, nil
}
