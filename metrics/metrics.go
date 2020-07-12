package metrics

import (
	"context"
	"net"
	"time"

	"github.com/lucas-clemente/quic-go/logging"

	"go.opencensus.io/stats"
	"go.opencensus.io/stats/view"
	"go.opencensus.io/tag"
)

// Measures
var (
	connections = stats.Int64("quic-go/connections", "number of QUIC connections", stats.UnitDimensionless)
)

// Tags
var (
	keyPerspective, _ = tag.NewKey("perspective")
	keyIPVersion, _   = tag.NewKey("ip_version")
)

// Views
var (
	ConnectionsView = &view.View{
		Measure:     connections,
		TagKeys:     []tag.Key{keyPerspective, keyIPVersion},
		Aggregation: view.Count(),
	}
)

// DefaultViews collects all OpenCensus views for metric gathering purposes
var DefaultViews = []*view.View{
	ConnectionsView,
}

type tracer struct{}

var _ logging.Tracer = &tracer{}

// NewTracer creates a new metrics tracer.
func NewTracer() logging.Tracer { return &tracer{} }

func (t *tracer) TracerForConnection(p logging.Perspective, _ logging.ConnectionID) logging.ConnectionTracer {
	return newConnTracer(t, p)
}

type connTracer struct {
	perspective logging.Perspective
	tracer      logging.Tracer
}

func newConnTracer(tracer logging.Tracer, perspective logging.Perspective) logging.ConnectionTracer {
	return &connTracer{
		perspective: perspective,
		tracer:      tracer,
	}
}

var _ logging.ConnectionTracer = &connTracer{}

func (t *connTracer) StartedConnection(local, _ net.Addr, _ logging.VersionNumber, _, _ logging.ConnectionID) {
	perspectiveTag := tag.Upsert(keyPerspective, perspective(t.perspective).String())

	var ipVersionTag tag.Mutator
	if udpAddr, ok := local.(*net.UDPAddr); ok {
		// If ip is not an IPv4 address, To4 returns nil.
		// Note that there might be some corner cases, where this is not correct.
		// See https://stackoverflow.com/questions/22751035/golang-distinguish-ipv4-ipv6.
		if udpAddr.IP.To4() == nil {
			ipVersionTag = tag.Upsert(keyIPVersion, "IPv6")
		} else {
			ipVersionTag = tag.Upsert(keyIPVersion, "IPv4")
		}
	} else {
		ipVersionTag = tag.Upsert(keyIPVersion, "unknown")
	}

	stats.RecordWithTags(
		context.Background(),
		[]tag.Mutator{perspectiveTag, ipVersionTag},
		connections.M(1),
	)
}

func (t *connTracer) ClosedConnection(logging.CloseReason)                     {}
func (t *connTracer) SentTransportParameters(*logging.TransportParameters)     {}
func (t *connTracer) ReceivedTransportParameters(*logging.TransportParameters) {}
func (t *connTracer) SentPacket(*logging.ExtendedHeader, logging.ByteCount, *logging.AckFrame, []logging.Frame) {
}
func (t *connTracer) ReceivedVersionNegotiationPacket(*logging.Header, []logging.VersionNumber) {}
func (t *connTracer) ReceivedRetry(*logging.Header)                                             {}
func (t *connTracer) ReceivedPacket(*logging.ExtendedHeader, logging.ByteCount, []logging.Frame) {
}
func (t *connTracer) BufferedPacket(logging.PacketType)                                             {}
func (t *connTracer) DroppedPacket(logging.PacketType, logging.ByteCount, logging.PacketDropReason) {}
func (t *connTracer) UpdatedMetrics(*logging.RTTStats, logging.ByteCount, logging.ByteCount, int)   {}
func (t *connTracer) LostPacket(logging.EncryptionLevel, logging.PacketNumber, logging.PacketLossReason) {
}
func (t *connTracer) UpdatedPTOCount(value uint32)                                       {}
func (t *connTracer) UpdatedKeyFromTLS(logging.EncryptionLevel, logging.Perspective)     {}
func (t *connTracer) UpdatedKey(logging.KeyPhase, bool)                                  {}
func (t *connTracer) DroppedEncryptionLevel(logging.EncryptionLevel)                     {}
func (t *connTracer) SetLossTimer(logging.TimerType, logging.EncryptionLevel, time.Time) {}
func (t *connTracer) LossTimerExpired(logging.TimerType, logging.EncryptionLevel)        {}
func (t *connTracer) LossTimerCanceled()                                                 {}
func (t *connTracer) Close()                                                             {}
