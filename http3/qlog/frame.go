package qlog

import (
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/qlogwriter/jsontext"
)

// Frame represents an HTTP/3 frame.
type Frame struct {
	Frame any
}

func (f Frame) encode(enc *jsontext.Encoder) error {
	switch frame := f.Frame.(type) {
	case DataFrame:
		return frame.encode(enc)
	case HeadersFrame:
		return frame.encode(enc)
	case GoAwayFrame:
		return frame.encode(enc)
	}
	// This shouldn't happen if the code is correctly logging frames.
	// Write a null token to produce valid JSON.
	return enc.WriteToken(jsontext.Null)
}

// A DataFrame is a DATA frame
type DataFrame struct{}

func (f *DataFrame) encode(enc *jsontext.Encoder) error {
	h := encoderHelper{enc: enc}
	h.WriteToken(jsontext.BeginObject)
	h.WriteToken(jsontext.String("frame_type"))
	h.WriteToken(jsontext.String("data"))
	h.WriteToken(jsontext.EndObject)
	return h.err
}

type HeaderField struct {
	Name  string
	Value string
}

// A HeadersFrame is a HEADERS frame
type HeadersFrame struct {
	HeaderFields []HeaderField
}

func (f *HeadersFrame) encode(enc *jsontext.Encoder) error {
	h := encoderHelper{enc: enc}
	h.WriteToken(jsontext.BeginObject)
	h.WriteToken(jsontext.String("frame_type"))
	h.WriteToken(jsontext.String("headers"))
	if len(f.HeaderFields) > 0 {
		h.WriteToken(jsontext.String("header_fields"))
		h.WriteToken(jsontext.BeginArray)
		for _, f := range f.HeaderFields {
			h.WriteToken(jsontext.BeginObject)
			h.WriteToken(jsontext.String("name"))
			h.WriteToken(jsontext.String(f.Name))
			h.WriteToken(jsontext.String("value"))
			h.WriteToken(jsontext.String(f.Value))
			h.WriteToken(jsontext.EndObject)
		}
		h.WriteToken(jsontext.EndArray)
	}
	h.WriteToken(jsontext.EndObject)
	return h.err
}

// A GoAwayFrame is a GOAWAY frame
type GoAwayFrame struct {
	StreamID quic.StreamID
}

func (f *GoAwayFrame) encode(enc *jsontext.Encoder) error {
	h := encoderHelper{enc: enc}
	h.WriteToken(jsontext.BeginObject)
	h.WriteToken(jsontext.String("frame_type"))
	h.WriteToken(jsontext.String("goaway"))
	h.WriteToken(jsontext.String("id"))
	h.WriteToken(jsontext.Uint(uint64(f.StreamID)))
	h.WriteToken(jsontext.EndObject)
	return h.err
}
