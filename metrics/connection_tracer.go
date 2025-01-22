package metrics

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/internal/qerr"
	"github.com/quic-go/quic-go/logging"

	"github.com/prometheus/client_golang/prometheus"
)

var (
	connStarted = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: metricNamespace,
			Name:      "connections_started_total",
			Help:      "Connections Started",
		},
		[]string{"dir"},
	)
	connClosed = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: metricNamespace,
			Name:      "connections_closed_total",
			Help:      "Connections Closed",
		},
		[]string{"dir", "reason"},
	)
	connDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: metricNamespace,
			Name:      "connection_duration_seconds",
			Help:      "Duration of a Connection",
			Buckets:   prometheus.ExponentialBuckets(1.0/16, 2, 25), // up to 24 days
		},
		[]string{"dir"},
	)
	connHandshakeDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: metricNamespace,
			Name:      "handshake_duration_seconds",
			Help:      "Duration of the QUIC Handshake",
			Buckets:   prometheus.ExponentialBuckets(0.001, 1.3, 35),
		},
		[]string{"dir"},
	)
	packetsSent = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: metricNamespace,
			Name:      "packets_sent_total",
			Help:      "Packets Sent",
		},
		[]string{"type"},
	)
	packetsReceived = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: metricNamespace,
			Name:      "packets_received_total",
			Help:      "Packets Received",
		},
		[]string{"type"},
	)
)

// DefaultConnectionTracer returns a callback that creates a metrics ConnectionTracer.
// The ConnectionTracer returned can be set on the quic.Config for a new connection.
func DefaultConnectionTracer(_ context.Context, p logging.Perspective, _ logging.ConnectionID) *logging.ConnectionTracer {
	switch p {
	case logging.PerspectiveClient:
		return NewClientConnectionTracerWithRegisterer(prometheus.DefaultRegisterer)
	case logging.PerspectiveServer:
		return NewServerConnectionTracerWithRegisterer(prometheus.DefaultRegisterer)
	default:
		panic("invalid perspective")
	}
}

// NewClientConnectionTracerWithRegisterer creates a new connection tracer for a connection
// dialed on the client side with a given Prometheus registerer.
func NewClientConnectionTracerWithRegisterer(registerer prometheus.Registerer) *logging.ConnectionTracer {
	return newConnectionTracerWithRegisterer(registerer, true)
}

// NewServerConnectionTracerWithRegisterer creates a new connection tracer for a connection
// accepted on the server side with a given Prometheus registerer.
func NewServerConnectionTracerWithRegisterer(registerer prometheus.Registerer) *logging.ConnectionTracer {
	return newConnectionTracerWithRegisterer(registerer, false)
}

func newConnectionTracerWithRegisterer(registerer prometheus.Registerer, isClient bool) *logging.ConnectionTracer {
	for _, c := range [...]prometheus.Collector{
		connStarted,
		connHandshakeDuration,
		connClosed,
		connDuration,
		packetsSent,
		packetsReceived,
	} {
		if err := registerer.Register(c); err != nil {
			if ok := errors.As(err, &prometheus.AlreadyRegisteredError{}); !ok {
				panic(err)
			}
		}
	}

	direction := "incoming"
	if isClient {
		direction = "outgoing"
	}

	var (
		startTime         time.Time
		handshakeComplete bool
	)
	return &logging.ConnectionTracer{
		StartedConnection: func(_, _ net.Addr, _, _ logging.ConnectionID) {
			tags := getStringSlice()
			defer putStringSlice(tags)

			startTime = time.Now()

			*tags = append(*tags, direction)
			connStarted.WithLabelValues(*tags...).Inc()
		},
		ClosedConnection: func(e error) {
			tags := getStringSlice()
			defer putStringSlice(tags)

			*tags = append(*tags, direction)
			// call connDuration.Observe before adding any more labels
			if handshakeComplete {
				connDuration.WithLabelValues(*tags...).Observe(time.Since(startTime).Seconds())
			}

			var (
				statelessResetErr     *quic.StatelessResetError
				handshakeTimeoutErr   *quic.HandshakeTimeoutError
				idleTimeoutErr        *quic.IdleTimeoutError
				applicationErr        *quic.ApplicationError
				transportErr          *quic.TransportError
				versionNegotiationErr *quic.VersionNegotiationError
			)
			var reason string
			switch {
			case errors.As(e, &statelessResetErr):
				reason = "stateless_reset"
			case errors.As(e, &handshakeTimeoutErr):
				reason = "handshake_timeout"
			case errors.As(e, &idleTimeoutErr):
				if handshakeComplete {
					reason = "idle_timeout"
				} else {
					reason = "handshake_timeout"
				}
			case errors.As(e, &applicationErr):
				if applicationErr.Remote {
					reason = "application_error (remote)"
				} else {
					reason = "application_error (local)"
				}
			case errors.As(e, &transportErr):
				switch {
				case transportErr.ErrorCode == qerr.ApplicationErrorErrorCode:
					if transportErr.Remote {
						reason = "application_error (remote)"
					} else {
						reason = "application_error (local)"
					}
				case transportErr.ErrorCode.IsCryptoError():
					if transportErr.Remote {
						reason = "crypto_error (remote)"
					} else {
						reason = "crypto_error (local)"
					}
				default:
					if transportErr.Remote {
						reason = "transport_error (remote)"
					} else {
						reason = fmt.Sprintf("transport_error (local): %s", transportErr.ErrorCode)
					}
				}
			case errors.As(e, &versionNegotiationErr):
				reason = "version_mismatch"
			default:
				reason = "unknown"
			}
			*tags = append(*tags, reason)
			connClosed.WithLabelValues(*tags...).Inc()
		},
		UpdatedKeyFromTLS: func(l logging.EncryptionLevel, p logging.Perspective) {
			// The client derives both 1-RTT keys when the handshake completes.
			// The server derives the 1-RTT read key when the handshake completes.
			if l != logging.Encryption1RTT || p != logging.PerspectiveClient {
				return
			}
			handshakeComplete = true

			tags := getStringSlice()
			defer putStringSlice(tags)

			*tags = append(*tags, direction)
			connHandshakeDuration.WithLabelValues(*tags...).Observe(time.Since(startTime).Seconds())
		},
		SentLongHeaderPacket: func(hdr *logging.ExtendedHeader, _ logging.ByteCount, _ logging.ECN, _ *logging.AckFrame, _ []logging.Frame) {
			tags := getStringSlice()
			defer putStringSlice(tags)

			*tags = append(*tags, longHeaderType(hdr))
			packetsSent.WithLabelValues(*tags...).Inc()
		},
		SentShortHeaderPacket: func(*logging.ShortHeader, logging.ByteCount, logging.ECN, *logging.AckFrame, []logging.Frame) {
			tags := getStringSlice()
			defer putStringSlice(tags)

			*tags = append(*tags, "1rtt")
			packetsSent.WithLabelValues(*tags...).Inc()
		},
		ReceivedLongHeaderPacket: func(hdr *logging.ExtendedHeader, _ logging.ByteCount, _ logging.ECN, _ []logging.Frame) {
			tags := getStringSlice()
			defer putStringSlice(tags)

			*tags = append(*tags, longHeaderType(hdr))
			packetsReceived.WithLabelValues(*tags...).Inc()
		},
		ReceivedShortHeaderPacket: func(*logging.ShortHeader, logging.ByteCount, logging.ECN, []logging.Frame) {
			tags := getStringSlice()
			defer putStringSlice(tags)

			*tags = append(*tags, "1rtt")
			packetsReceived.WithLabelValues(*tags...).Inc()
		},
	}
}

func longHeaderType(hdr *logging.ExtendedHeader) string {
	//nolint:exhaustive // only these packet types are of interest
	switch logging.PacketTypeFromHeader(&hdr.Header) {
	case logging.PacketTypeRetry:
		return "retry"
	case logging.PacketTypeInitial:
		return "initial"
	case logging.PacketTypeHandshake:
		return "handshake"
	case logging.PacketType0RTT:
		return "0rtt"
	case logging.PacketTypeStatelessReset:
		return "stateless_reset"
	case logging.PacketTypeVersionNegotiation:
		return "version_negotiation"
	}
	return "unknown"
}
