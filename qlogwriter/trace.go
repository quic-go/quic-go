package qlogwriter

import (
	"runtime/debug"
	"time"

	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/qlogwriter/jsontext"
)

type ConnectionID = protocol.ConnectionID

// Setting of this only works when quic-go is used as a library.
// When building a binary from this repository, the version can be set using the following go build flag:
// -ldflags="-X github.com/quic-go/quic-go/qlogwriter.quicGoVersion=foobar"
var quicGoVersion = "(devel)"

func init() {
	if quicGoVersion != "(devel)" { // variable set by ldflags
		return
	}
	info, ok := debug.ReadBuildInfo()
	if !ok { // no build info available. This happens when quic-go is not used as a library.
		return
	}
	for _, d := range info.Deps {
		if d.Path == "github.com/quic-go/quic-go" {
			quicGoVersion = d.Version
			if d.Replace != nil {
				if len(d.Replace.Version) > 0 {
					quicGoVersion = d.Version
				} else {
					quicGoVersion += " (replaced)"
				}
			}
			break
		}
	}
}

type topLevel struct {
	trace trace
}

func (l topLevel) Encode(enc *jsontext.Encoder) error {
	h := encoderHelper{enc: enc}
	h.WriteToken(jsontext.BeginObject)
	h.WriteToken(jsontext.String("qlog_format"))
	h.WriteToken(jsontext.String("JSON-SEQ"))
	h.WriteToken(jsontext.String("qlog_version"))
	h.WriteToken(jsontext.String("0.3"))
	h.WriteToken(jsontext.String("title"))
	h.WriteToken(jsontext.String("quic-go qlog"))
	h.WriteToken(jsontext.String("configuration"))
	if err := (configuration{Version: quicGoVersion}).Encode(enc); err != nil {
		return err
	}
	h.WriteToken(jsontext.String("trace"))
	if err := l.trace.Encode(enc); err != nil {
		return err
	}
	h.WriteToken(jsontext.EndObject)
	return h.err
}

type configuration struct {
	Version string
}

func (c configuration) Encode(enc *jsontext.Encoder) error {
	h := encoderHelper{enc: enc}
	h.WriteToken(jsontext.BeginObject)
	h.WriteToken(jsontext.String("code_version"))
	h.WriteToken(jsontext.String(c.Version))
	h.WriteToken(jsontext.EndObject)
	return h.err
}

type vantagePoint struct {
	Name string
	Type string
}

func (p vantagePoint) Encode(enc *jsontext.Encoder) error {
	h := encoderHelper{enc: enc}
	h.WriteToken(jsontext.BeginObject)
	if p.Name != "" {
		h.WriteToken(jsontext.String("name"))
		h.WriteToken(jsontext.String(p.Name))
	}
	if p.Type != "" {
		h.WriteToken(jsontext.String("type"))
		h.WriteToken(jsontext.String(p.Type))
	}
	h.WriteToken(jsontext.EndObject)
	return h.err
}

type commonFields struct {
	ODCID         *ConnectionID
	GroupID       *ConnectionID
	ProtocolType  string
	ReferenceTime time.Time
}

func (f commonFields) Encode(enc *jsontext.Encoder) error {
	h := encoderHelper{enc: enc}
	h.WriteToken(jsontext.BeginObject)
	if f.ODCID != nil {
		h.WriteToken(jsontext.String("ODCID"))
		h.WriteToken(jsontext.String(f.ODCID.String()))
		h.WriteToken(jsontext.String("group_id"))
		h.WriteToken(jsontext.String(f.ODCID.String()))
	}
	if f.ProtocolType != "" {
		h.WriteToken(jsontext.String("protocol_type"))
		h.WriteToken(jsontext.String(f.ProtocolType))
	}
	h.WriteToken(jsontext.String("reference_time"))
	h.WriteToken(jsontext.Float(float64(f.ReferenceTime.UnixNano()) / 1e6))
	h.WriteToken(jsontext.String("time_format"))
	h.WriteToken(jsontext.String("relative"))
	h.WriteToken(jsontext.EndObject)
	return h.err
}

type trace struct {
	VantagePoint vantagePoint
	CommonFields commonFields
}

func (t trace) Encode(enc *jsontext.Encoder) error {
	h := encoderHelper{enc: enc}
	h.WriteToken(jsontext.BeginObject)
	h.WriteToken(jsontext.String("vantage_point"))
	if err := t.VantagePoint.Encode(enc); err != nil {
		return err
	}
	h.WriteToken(jsontext.String("common_fields"))
	if err := t.CommonFields.Encode(enc); err != nil {
		return err
	}
	h.WriteToken(jsontext.EndObject)
	return h.err
}
