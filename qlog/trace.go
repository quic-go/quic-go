package qlog

import (
	"time"

	"github.com/francoispqt/gojay"

	"github.com/lucas-clemente/quic-go/internal/protocol"
)

type topLevel struct {
	traces traces
}

func (topLevel) IsNil() bool { return false }
func (l topLevel) MarshalJSONObject(enc *gojay.Encoder) {
	enc.StringKey("qlog_version", "draft-02-wip")
	enc.StringKeyOmitEmpty("title", "quic-go qlog")
	enc.ArrayKey("traces", l.traces)
}

type vantagePoint struct {
	Name string
	Type protocol.Perspective
}

func (p vantagePoint) IsNil() bool { return false }
func (p vantagePoint) MarshalJSONObject(enc *gojay.Encoder) {
	enc.StringKeyOmitEmpty("name", p.Name)
	switch p.Type {
	case protocol.PerspectiveClient:
		enc.StringKey("type", "client")
	case protocol.PerspectiveServer:
		enc.StringKey("type", "server")
	}
}

type commonFields struct {
	ODCID         connectionID
	GroupID       connectionID
	ProtocolType  string
	ReferenceTime time.Time
}

func (f commonFields) MarshalJSONObject(enc *gojay.Encoder) {
	enc.StringKey("ODCID", f.ODCID.String())
	enc.StringKey("group_id", f.ODCID.String())
	enc.StringKeyOmitEmpty("protocol_type", f.ProtocolType)
	enc.Float64Key("reference_time", float64(f.ReferenceTime.UnixNano())/1e6)
}

func (f commonFields) IsNil() bool { return false }

type traces []trace

func (t traces) IsNil() bool { return t == nil }
func (t traces) MarshalJSONArray(enc *gojay.Encoder) {
	for _, tr := range t {
		enc.Object(tr)
	}
}

type trace struct {
	VantagePoint vantagePoint
	CommonFields commonFields
	EventFields  []string
	Events       events
}

func (trace) IsNil() bool { return false }
func (t trace) MarshalJSONObject(enc *gojay.Encoder) {
	enc.ObjectKey("vantage_point", t.VantagePoint)
	enc.ObjectKey("common_fields", t.CommonFields)
	enc.SliceStringKey("event_fields", t.EventFields)
	enc.ArrayKey("events", t.Events)
}
