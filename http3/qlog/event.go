package qlog

import (
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/qlogwriter"
	"github.com/quic-go/quic-go/qlogwriter/jsontext"
)

// EventSchema is the qlog event schema for HTTP/3
const EventSchema = "urn:ietf:params:qlog:events:http3-12"

func init() {
	qlogwriter.RegisterEventSchema(EventSchema)
}

type encoderHelper struct {
	enc *jsontext.Encoder
	err error
}

func (h *encoderHelper) WriteToken(t jsontext.Token) {
	if h.err != nil {
		return
	}
	h.err = h.enc.WriteToken(t)
}

// OmitLength indicates that a length should not be logged.
const OmitLength = -1

// RawInfo contains frame or datagram lengths. Zero lengths are logged.
// Set a field to OmitLength to omit it.
type RawInfo struct {
	Length        int // full frame or datagram length, including its header
	PayloadLength int // length of the payload, excluding the header
}

func (i RawInfo) HasValues() bool {
	return i.Length != OmitLength || i.PayloadLength != OmitLength
}

func (i RawInfo) encode(enc *jsontext.Encoder) error {
	h := encoderHelper{enc: enc}
	h.WriteToken(jsontext.BeginObject)
	if i.Length != OmitLength {
		h.WriteToken(jsontext.String("length"))
		h.WriteToken(jsontext.Uint(uint64(i.Length)))
	}
	if i.PayloadLength != OmitLength {
		h.WriteToken(jsontext.String("payload_length"))
		h.WriteToken(jsontext.Uint(uint64(i.PayloadLength)))
	}
	h.WriteToken(jsontext.EndObject)
	return h.err
}

type FrameParsed struct {
	StreamID quic.StreamID
	Raw      RawInfo
	Frame    Frame
}

func (e FrameParsed) Name() string { return "http3:frame_parsed" }

func (e FrameParsed) Encode(enc *jsontext.Encoder, _ time.Time) error {
	h := encoderHelper{enc: enc}
	h.WriteToken(jsontext.BeginObject)
	h.WriteToken(jsontext.String("stream_id"))
	h.WriteToken(jsontext.Uint(uint64(e.StreamID)))
	h.WriteToken(jsontext.String("frame"))
	if err := e.Frame.encode(enc, e.Raw); err != nil {
		return err
	}
	h.WriteToken(jsontext.EndObject)
	return h.err
}

type FrameCreated struct {
	StreamID quic.StreamID
	Raw      RawInfo
	Frame    Frame
}

func (e FrameCreated) Name() string { return "http3:frame_created" }

func (e FrameCreated) Encode(enc *jsontext.Encoder, _ time.Time) error {
	h := encoderHelper{enc: enc}
	h.WriteToken(jsontext.BeginObject)
	h.WriteToken(jsontext.String("stream_id"))
	h.WriteToken(jsontext.Uint(uint64(e.StreamID)))
	h.WriteToken(jsontext.String("frame"))
	if err := e.Frame.encode(enc, e.Raw); err != nil {
		return err
	}
	h.WriteToken(jsontext.EndObject)
	return h.err
}

type DatagramCreated struct {
	QuarterStreamID uint64
	Raw             RawInfo
}

func (e DatagramCreated) Name() string { return "http3:datagram_created" }

func (e DatagramCreated) Encode(enc *jsontext.Encoder, _ time.Time) error {
	h := encoderHelper{enc: enc}
	h.WriteToken(jsontext.BeginObject)
	h.WriteToken(jsontext.String("quarter_stream_id"))
	h.WriteToken(jsontext.Uint(e.QuarterStreamID))
	h.WriteToken(jsontext.String("raw"))
	if err := e.Raw.encode(enc); err != nil {
		return err
	}
	h.WriteToken(jsontext.EndObject)
	return h.err
}

type DatagramParsed struct {
	QuarterStreamID uint64
	Raw             RawInfo
}

func (e DatagramParsed) Name() string { return "http3:datagram_parsed" }

func (e DatagramParsed) Encode(enc *jsontext.Encoder, _ time.Time) error {
	h := encoderHelper{enc: enc}
	h.WriteToken(jsontext.BeginObject)
	h.WriteToken(jsontext.String("quarter_stream_id"))
	h.WriteToken(jsontext.Uint(e.QuarterStreamID))
	h.WriteToken(jsontext.String("raw"))
	if err := e.Raw.encode(enc); err != nil {
		return err
	}
	h.WriteToken(jsontext.EndObject)
	return h.err
}
