package metrics

import (
	"context"
	"errors"
	"net"
	"time"

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
		[]string{"dir"},
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
)

// DefaultTracer returns a callback that creates a metrics ConnectionTracer.
// The ConnectionTracer returned can be set on the quic.Config for a new connection.
// It should be reused across QUIC connections.
func DefaultTracer() func(_ context.Context, p logging.Perspective, _ logging.ConnectionID) *logging.ConnectionTracer {
	return DefaultTracerWithRegisterer(prometheus.DefaultRegisterer)
}

// DefaultTracerWithRegisterer returns a callback that creates a metrics ConnectionTracer
// using a given Prometheus registerer.
func DefaultTracerWithRegisterer(registerer prometheus.Registerer) func(_ context.Context, p logging.Perspective, _ logging.ConnectionID) *logging.ConnectionTracer {
	return func(_ context.Context, p logging.Perspective, _ logging.ConnectionID) *logging.ConnectionTracer {
		switch p {
		case logging.PerspectiveClient:
			return NewClientConnectionTracerWithRegisterer(registerer)
		case logging.PerspectiveServer:
			return NewServerConnectionTracerWithRegisterer(registerer)
		default:
			panic("invalid perspective")
		}
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
		ClosedConnection: func(_ error) {
			tags := getStringSlice()
			defer putStringSlice(tags)

			*tags = append(*tags, direction)
			connClosed.WithLabelValues(*tags...).Inc()
			if handshakeComplete {
				connDuration.WithLabelValues(*tags...).Observe(time.Since(startTime).Seconds())
			}
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
	}
}
