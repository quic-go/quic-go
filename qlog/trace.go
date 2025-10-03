package qlog

import (
	"runtime/debug"
	"time"

	"github.com/quic-go/quic-go/logging"

	"github.com/quic-go/json/jsontext"
)

// Setting of this only works when quic-go is used as a library.
// When building a binary from this repository, the version can be set using the following go build flag:
// -ldflags="-X github.com/quic-go/quic-go/qlog.quicGoVersion=foobar"
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
	if err := enc.WriteToken(jsontext.BeginObject); err != nil {
		return err
	}
	if err := enc.WriteToken(jsontext.String("qlog_format")); err != nil {
		return err
	}
	if err := enc.WriteToken(jsontext.String("JSON-SEQ")); err != nil {
		return err
	}
	if err := enc.WriteToken(jsontext.String("qlog_version")); err != nil {
		return err
	}
	if err := enc.WriteToken(jsontext.String("0.3")); err != nil {
		return err
	}
	if err := enc.WriteToken(jsontext.String("title")); err != nil {
		return err
	}
	if err := enc.WriteToken(jsontext.String("quic-go qlog")); err != nil {
		return err
	}
	if err := enc.WriteToken(jsontext.String("configuration")); err != nil {
		return err
	}
	if err := (configuration{Version: quicGoVersion}).Encode(enc); err != nil {
		return err
	}
	if err := enc.WriteToken(jsontext.String("trace")); err != nil {
		return err
	}
	if err := l.trace.Encode(enc); err != nil {
		return err
	}
	return enc.WriteToken(jsontext.EndObject)
}

type configuration struct {
	Version string
}

func (c configuration) Encode(enc *jsontext.Encoder) error {
	if err := enc.WriteToken(jsontext.BeginObject); err != nil {
		return err
	}
	if err := enc.WriteToken(jsontext.String("code_version")); err != nil {
		return err
	}
	if err := enc.WriteToken(jsontext.String(c.Version)); err != nil {
		return err
	}
	return enc.WriteToken(jsontext.EndObject)
}

type vantagePoint struct {
	Name string
	Type string
}

func (p vantagePoint) Encode(enc *jsontext.Encoder) error {
	if err := enc.WriteToken(jsontext.BeginObject); err != nil {
		return err
	}
	if p.Name != "" {
		if err := enc.WriteToken(jsontext.String("name")); err != nil {
			return err
		}
		if err := enc.WriteToken(jsontext.String(p.Name)); err != nil {
			return err
		}
	}
	if p.Type != "" {
		if err := enc.WriteToken(jsontext.String("type")); err != nil {
			return err
		}
		if err := enc.WriteToken(jsontext.String(p.Type)); err != nil {
			return err
		}
	}
	return enc.WriteToken(jsontext.EndObject)
}

type commonFields struct {
	ODCID         *logging.ConnectionID
	GroupID       *logging.ConnectionID
	ProtocolType  string
	ReferenceTime time.Time
}

func (f commonFields) Encode(enc *jsontext.Encoder) error {
	if err := enc.WriteToken(jsontext.BeginObject); err != nil {
		return err
	}
	if f.ODCID != nil {
		if err := enc.WriteToken(jsontext.String("ODCID")); err != nil {
			return err
		}
		if err := enc.WriteToken(jsontext.String(f.ODCID.String())); err != nil {
			return err
		}
		if err := enc.WriteToken(jsontext.String("group_id")); err != nil {
			return err
		}
		if err := enc.WriteToken(jsontext.String(f.ODCID.String())); err != nil {
			return err
		}
	}
	if f.ProtocolType != "" {
		if err := enc.WriteToken(jsontext.String("protocol_type")); err != nil {
			return err
		}
		if err := enc.WriteToken(jsontext.String(f.ProtocolType)); err != nil {
			return err
		}
	}
	if err := enc.WriteToken(jsontext.String("reference_time")); err != nil {
		return err
	}
	if err := enc.WriteToken(jsontext.Float(float64(f.ReferenceTime.UnixNano()) / 1e6)); err != nil {
		return err
	}
	if err := enc.WriteToken(jsontext.String("time_format")); err != nil {
		return err
	}
	if err := enc.WriteToken(jsontext.String("relative")); err != nil {
		return err
	}
	return enc.WriteToken(jsontext.EndObject)
}

type trace struct {
	VantagePoint vantagePoint
	CommonFields commonFields
}

func (t trace) Encode(enc *jsontext.Encoder) error {
	if err := enc.WriteToken(jsontext.BeginObject); err != nil {
		return err
	}
	if err := enc.WriteToken(jsontext.String("vantage_point")); err != nil {
		return err
	}
	if err := t.VantagePoint.Encode(enc); err != nil {
		return err
	}
	if err := enc.WriteToken(jsontext.String("common_fields")); err != nil {
		return err
	}
	if err := t.CommonFields.Encode(enc); err != nil {
		return err
	}
	return enc.WriteToken(jsontext.EndObject)
}
