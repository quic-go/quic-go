package qlog

import (
	"runtime/debug"
	"time"

	"github.com/quic-go/quic-go/logging"

	"github.com/francoispqt/gojay"
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

func (topLevel) IsNil() bool { return false }
func (l topLevel) MarshalJSONObject(enc *gojay.Encoder) {
	enc.StringKey("qlog_format", "JSON-SEQ")
	enc.StringKey("qlog_version", "0.3")
	enc.StringKeyOmitEmpty("title", "quic-go qlog")
	enc.ObjectKey("configuration", configuration{Version: quicGoVersion})
	enc.ObjectKey("trace", l.trace)
}

type configuration struct {
	Version string
}

func (c configuration) IsNil() bool { return false }
func (c configuration) MarshalJSONObject(enc *gojay.Encoder) {
	enc.StringKey("code_version", c.Version)
}

type vantagePoint struct {
	Name string
	Type string
}

func (p vantagePoint) IsNil() bool { return false }
func (p vantagePoint) MarshalJSONObject(enc *gojay.Encoder) {
	enc.StringKeyOmitEmpty("name", p.Name)
	enc.StringKeyOmitEmpty("type", p.Type)
}

type commonFields struct {
	ODCID         *logging.ConnectionID
	GroupID       *logging.ConnectionID
	ProtocolType  string
	ReferenceTime time.Time
}

func (f commonFields) MarshalJSONObject(enc *gojay.Encoder) {
	if f.ODCID != nil {
		enc.StringKey("ODCID", f.ODCID.String())
		enc.StringKey("group_id", f.ODCID.String())
	}
	enc.StringKeyOmitEmpty("protocol_type", f.ProtocolType)
	enc.Float64Key("reference_time", float64(f.ReferenceTime.UnixNano())/1e6)
	enc.StringKey("time_format", "relative")
}

func (f commonFields) IsNil() bool { return false }

type trace struct {
	VantagePoint vantagePoint
	CommonFields commonFields
}

func (trace) IsNil() bool { return false }
func (t trace) MarshalJSONObject(enc *gojay.Encoder) {
	enc.ObjectKey("vantage_point", t.VantagePoint)
	enc.ObjectKey("common_fields", t.CommonFields)
}
