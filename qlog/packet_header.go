package qlog

import (
	"fmt"

	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/logging"

	"github.com/quic-go/json/jsontext"
)

func getPacketTypeFromEncryptionLevel(encLevel protocol.EncryptionLevel) logging.PacketType {
	switch encLevel {
	case protocol.EncryptionInitial:
		return logging.PacketTypeInitial
	case protocol.EncryptionHandshake:
		return logging.PacketTypeHandshake
	case protocol.Encryption0RTT:
		return logging.PacketType0RTT
	case protocol.Encryption1RTT:
		return logging.PacketType1RTT
	default:
		panic("unknown encryption level")
	}
}

type token struct {
	Raw []byte
}

func (t token) Encode(enc *jsontext.Encoder) error {
	if err := enc.WriteToken(jsontext.BeginObject); err != nil {
		return err
	}
	if err := enc.WriteToken(jsontext.String("data")); err != nil {
		return err
	}
	if err := enc.WriteToken(jsontext.String(fmt.Sprintf("%x", t.Raw))); err != nil {
		return err
	}
	return enc.WriteToken(jsontext.EndObject)
}

// PacketHeader is a QUIC packet header.
// TODO: make this a long header
type packetHeader struct {
	PacketType       logging.PacketType
	KeyPhaseBit      logging.KeyPhaseBit
	PacketNumber     logging.PacketNumber
	Version          logging.Version
	SrcConnectionID  logging.ConnectionID
	DestConnectionID logging.ConnectionID
	Token            *token
}

func transformHeader(hdr *logging.Header) *packetHeader {
	h := &packetHeader{
		PacketType:       logging.PacketTypeFromHeader(hdr),
		SrcConnectionID:  hdr.SrcConnectionID,
		DestConnectionID: hdr.DestConnectionID,
		Version:          hdr.Version,
	}
	if len(hdr.Token) > 0 {
		h.Token = &token{Raw: hdr.Token}
	}
	return h
}

func transformLongHeader(hdr *logging.ExtendedHeader) *packetHeader {
	h := transformHeader(&hdr.Header)
	h.PacketNumber = hdr.PacketNumber
	h.KeyPhaseBit = hdr.KeyPhase
	return h
}

func (h packetHeader) Encode(enc *jsontext.Encoder) error {
	if err := enc.WriteToken(jsontext.BeginObject); err != nil {
		return err
	}
	if err := enc.WriteToken(jsontext.String("packet_type")); err != nil {
		return err
	}
	if err := enc.WriteToken(jsontext.String(packetType(h.PacketType).String())); err != nil {
		return err
	}
	if h.PacketType != logging.PacketTypeRetry {
		if err := enc.WriteToken(jsontext.String("packet_number")); err != nil {
			return err
		}
		if err := enc.WriteToken(jsontext.Int(int64(h.PacketNumber))); err != nil {
			return err
		}
	}
	if h.Version != 0 {
		if err := enc.WriteToken(jsontext.String("version")); err != nil {
			return err
		}
		if err := enc.WriteToken(jsontext.String(version(h.Version).String())); err != nil {
			return err
		}
	}
	if h.PacketType != logging.PacketType1RTT {
		if err := enc.WriteToken(jsontext.String("scil")); err != nil {
			return err
		}
		if err := enc.WriteToken(jsontext.Int(int64(h.SrcConnectionID.Len()))); err != nil {
			return err
		}
		if h.SrcConnectionID.Len() > 0 {
			if err := enc.WriteToken(jsontext.String("scid")); err != nil {
				return err
			}
			if err := enc.WriteToken(jsontext.String(h.SrcConnectionID.String())); err != nil {
				return err
			}
		}
	}
	if err := enc.WriteToken(jsontext.String("dcil")); err != nil {
		return err
	}
	if err := enc.WriteToken(jsontext.Int(int64(h.DestConnectionID.Len()))); err != nil {
		return err
	}
	if h.DestConnectionID.Len() > 0 {
		if err := enc.WriteToken(jsontext.String("dcid")); err != nil {
			return err
		}
		if err := enc.WriteToken(jsontext.String(h.DestConnectionID.String())); err != nil {
			return err
		}
	}
	if h.KeyPhaseBit == logging.KeyPhaseZero || h.KeyPhaseBit == logging.KeyPhaseOne {
		if err := enc.WriteToken(jsontext.String("key_phase_bit")); err != nil {
			return err
		}
		if err := enc.WriteToken(jsontext.String(h.KeyPhaseBit.String())); err != nil {
			return err
		}
	}
	if h.Token != nil {
		if err := enc.WriteToken(jsontext.String("token")); err != nil {
			return err
		}
		if err := h.Token.Encode(enc); err != nil {
			return err
		}
	}
	return enc.WriteToken(jsontext.EndObject)
}

type packetHeaderVersionNegotiation struct {
	SrcConnectionID  logging.ArbitraryLenConnectionID
	DestConnectionID logging.ArbitraryLenConnectionID
}

func (h packetHeaderVersionNegotiation) Encode(enc *jsontext.Encoder) error {
	if err := enc.WriteToken(jsontext.BeginObject); err != nil {
		return err
	}
	if err := enc.WriteToken(jsontext.String("packet_type")); err != nil {
		return err
	}
	if err := enc.WriteToken(jsontext.String("version_negotiation")); err != nil {
		return err
	}
	if err := enc.WriteToken(jsontext.String("scil")); err != nil {
		return err
	}
	if err := enc.WriteToken(jsontext.Int(int64(h.SrcConnectionID.Len()))); err != nil {
		return err
	}
	if err := enc.WriteToken(jsontext.String("scid")); err != nil {
		return err
	}
	if err := enc.WriteToken(jsontext.String(h.SrcConnectionID.String())); err != nil {
		return err
	}
	if err := enc.WriteToken(jsontext.String("dcil")); err != nil {
		return err
	}
	if err := enc.WriteToken(jsontext.Int(int64(h.DestConnectionID.Len()))); err != nil {
		return err
	}
	if err := enc.WriteToken(jsontext.String("dcid")); err != nil {
		return err
	}
	if err := enc.WriteToken(jsontext.String(h.DestConnectionID.String())); err != nil {
		return err
	}
	return enc.WriteToken(jsontext.EndObject)
}

// a minimal header that only outputs the packet type, and potentially a packet number
type packetHeaderWithType struct {
	PacketType   logging.PacketType
	PacketNumber logging.PacketNumber
}

func (h packetHeaderWithType) Encode(enc *jsontext.Encoder) error {
	if err := enc.WriteToken(jsontext.BeginObject); err != nil {
		return err
	}
	if err := enc.WriteToken(jsontext.String("packet_type")); err != nil {
		return err
	}
	if err := enc.WriteToken(jsontext.String(packetType(h.PacketType).String())); err != nil {
		return err
	}
	if h.PacketNumber != protocol.InvalidPacketNumber {
		if err := enc.WriteToken(jsontext.String("packet_number")); err != nil {
			return err
		}
		if err := enc.WriteToken(jsontext.Int(int64(h.PacketNumber))); err != nil {
			return err
		}
	}
	return enc.WriteToken(jsontext.EndObject)
}

// a minimal header that only outputs the packet type
type packetHeaderWithTypeAndPacketNumber struct {
	PacketType   logging.PacketType
	PacketNumber logging.PacketNumber
}

func (h packetHeaderWithTypeAndPacketNumber) Encode(enc *jsontext.Encoder) error {
	if err := enc.WriteToken(jsontext.BeginObject); err != nil {
		return err
	}
	if err := enc.WriteToken(jsontext.String("packet_type")); err != nil {
		return err
	}
	if err := enc.WriteToken(jsontext.String(packetType(h.PacketType).String())); err != nil {
		return err
	}
	if err := enc.WriteToken(jsontext.String("packet_number")); err != nil {
		return err
	}
	if err := enc.WriteToken(jsontext.Int(int64(h.PacketNumber))); err != nil {
		return err
	}
	return enc.WriteToken(jsontext.EndObject)
}

type shortHeader struct {
	DestConnectionID logging.ConnectionID
	PacketNumber     logging.PacketNumber
	KeyPhaseBit      logging.KeyPhaseBit
}

func transformShortHeader(hdr *logging.ShortHeader) *shortHeader {
	return &shortHeader{
		DestConnectionID: hdr.DestConnectionID,
		PacketNumber:     hdr.PacketNumber,
		KeyPhaseBit:      hdr.KeyPhase,
	}
}

func (h shortHeader) Encode(enc *jsontext.Encoder) error {
	if err := enc.WriteToken(jsontext.BeginObject); err != nil {
		return err
	}
	if err := enc.WriteToken(jsontext.String("packet_type")); err != nil {
		return err
	}
	if err := enc.WriteToken(jsontext.String(packetType(logging.PacketType1RTT).String())); err != nil {
		return err
	}
	if h.DestConnectionID.Len() > 0 {
		if err := enc.WriteToken(jsontext.String("dcid")); err != nil {
			return err
		}
		if err := enc.WriteToken(jsontext.String(h.DestConnectionID.String())); err != nil {
			return err
		}
	}
	if err := enc.WriteToken(jsontext.String("packet_number")); err != nil {
		return err
	}
	if err := enc.WriteToken(jsontext.Int(int64(h.PacketNumber))); err != nil {
		return err
	}
	if err := enc.WriteToken(jsontext.String("key_phase_bit")); err != nil {
		return err
	}
	if err := enc.WriteToken(jsontext.String(h.KeyPhaseBit.String())); err != nil {
		return err
	}
	return enc.WriteToken(jsontext.EndObject)
}
