package quic

import (
	"bytes"
	"errors"
	"fmt"
	"io/ioutil"

	"github.com/lucas-clemente/quic-go/crypto"
	"github.com/lucas-clemente/quic-go/frames"
	"github.com/lucas-clemente/quic-go/protocol"
	"github.com/lucas-clemente/quic-go/qerr"
)

type unpackedPacket struct {
	entropyBit bool
	frames     []frames.Frame
}

type packetUnpacker struct {
	version protocol.VersionNumber
	aead    crypto.AEAD
}

func (u *packetUnpacker) Unpack(publicHeaderBinary []byte, hdr *publicHeader, r *bytes.Reader) (*unpackedPacket, error) {
	ciphertext, _ := ioutil.ReadAll(r)
	plaintext, err := u.aead.Open(hdr.PacketNumber, publicHeaderBinary, ciphertext)
	if err != nil {
		// Wrap err in quicError so that public reset is sent by session
		return nil, qerr.Error(qerr.DecryptionFailure, err.Error())
	}
	r = bytes.NewReader(plaintext)

	privateFlag, err := r.ReadByte()
	if err != nil {
		return nil, qerr.MissingPayload
	}
	entropyBit := privateFlag&0x01 > 0

	fs := make([]frames.Frame, 0, 1)

	// Read all frames in the packet
ReadLoop:
	for r.Len() > 0 {
		typeByte, _ := r.ReadByte()
		r.UnreadByte()

		var frame frames.Frame
		if typeByte&0x80 == 0x80 {
			frame, err = frames.ParseStreamFrame(r)
			if err != nil {
				err = qerr.Error(qerr.InvalidStreamData, err.Error())
			}
		} else if typeByte&0xc0 == 0x40 {
			frame, err = frames.ParseAckFrame(r, u.version)
			if err != nil {
				err = qerr.Error(qerr.InvalidAckData, err.Error())
			}
		} else if typeByte&0xe0 == 0x20 {
			err = errors.New("unimplemented: CONGESTION_FEEDBACK")
		} else {
			switch typeByte {
			case 0x0: // PAD, end of frames
				break ReadLoop
			case 0x01:
				frame, err = frames.ParseRstStreamFrame(r)
				if err != nil {
					err = qerr.Error(qerr.InvalidRstStreamData, err.Error())
				}
			case 0x02:
				frame, err = frames.ParseConnectionCloseFrame(r)
				if err != nil {
					err = qerr.Error(qerr.InvalidConnectionCloseData, err.Error())
				}
			case 0x03:
				frame, err = frames.ParseGoawayFrame(r)
				if err != nil {
					err = qerr.Error(qerr.InvalidGoawayData, err.Error())
				}
			case 0x04:
				frame, err = frames.ParseWindowUpdateFrame(r)
				if err != nil {
					err = qerr.Error(qerr.InvalidWindowUpdateData, err.Error())
				}
			case 0x05:
				frame, err = frames.ParseBlockedFrame(r)
				if err != nil {
					err = qerr.Error(qerr.InvalidBlockedData, err.Error())
				}
			case 0x06:
				frame, err = frames.ParseStopWaitingFrame(r, hdr.PacketNumber, hdr.PacketNumberLen)
				if err != nil {
					err = qerr.Error(qerr.InvalidStopWaitingData, err.Error())
				}
			case 0x07:
				frame, err = frames.ParsePingFrame(r)
			default:
				err = qerr.Error(qerr.InvalidFrameData, fmt.Sprintf("unknown type byte 0x%x", typeByte))
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
