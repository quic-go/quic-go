package metrics

import (
	"errors"
	"fmt"
	"net"

	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/qerr"
	"github.com/quic-go/quic-go/logging"

	"github.com/prometheus/client_golang/prometheus"
)

const metricNamespace = "quicgo"

func getIPVersion(addr net.Addr) string {
	udpAddr, ok := addr.(*net.UDPAddr)
	if !ok {
		return ""
	}
	if udpAddr.IP.To4() != nil {
		return "ipv4"
	}
	return "ipv6"
}

var (
	connsRejected = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: metricNamespace,
			Name:      "server_connections_rejected_total",
			Help:      "Connections Rejected",
		},
		[]string{"ip_version", "reason"},
	)
	packetDropped = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: metricNamespace,
			Name:      "server_received_packets_dropped_total",
			Help:      "packets dropped",
		},
		[]string{"ip_version", "reason"},
	)
)

// NewTracer creates a new tracer using the default Prometheus registerer.
// The Tracer returned from this function can be used to collect metrics for
// events happening before the establishment of a QUIC connection.
// It can be set on the Tracer field of quic.Transport.
func NewTracer() *logging.Tracer {
	return NewTracerWithRegisterer(prometheus.DefaultRegisterer)
}

// NewTracerWithRegisterer creates a new tracer using a given Prometheus registerer.
func NewTracerWithRegisterer(registerer prometheus.Registerer) *logging.Tracer {
	for _, c := range [...]prometheus.Collector{
		connsRejected,
		packetDropped,
	} {
		if err := registerer.Register(c); err != nil {
			if ok := errors.As(err, &prometheus.AlreadyRegisteredError{}); !ok {
				panic(err)
			}
		}
	}

	return &logging.Tracer{
		SentPacket: func(addr net.Addr, hdr *logging.Header, _ logging.ByteCount, frames []logging.Frame) {
			tags := getStringSlice()
			defer putStringSlice(tags)

			var reason string
			switch {
			case hdr.Type == protocol.PacketTypeRetry:
				reason = "retry"
			case hdr.Type == protocol.PacketTypeInitial:
				var ccf *logging.ConnectionCloseFrame
				for _, f := range frames {
					cc, ok := f.(*logging.ConnectionCloseFrame)
					if ok {
						ccf = cc
						break
					}
				}
				// This should never happen. We only send Initials before creating the connection in order to
				// reject a connection attempt.
				if ccf == nil {
					return
				}
				if ccf.IsApplicationError {
					//nolint:exhaustive // Only a few error codes applicable.
					switch qerr.TransportErrorCode(ccf.ErrorCode) {
					case qerr.ConnectionRefused:
						reason = "connection_refused"
					case qerr.InvalidToken:
						reason = "invalid_token"
					default:
						// This shouldn't happen, the server doesn't send CONNECTION_CLOSE frames with different errors.
						reason = fmt.Sprintf("transport_error: %d", ccf.ErrorCode)
					}
				} else {
					// This shouldn't happen, the server doesn't send application-level CONNECTION_CLOSE frames.
					reason = "application_error"
				}
			}
			*tags = append(*tags, getIPVersion(addr))
			*tags = append(*tags, reason)
			connsRejected.WithLabelValues(*tags...).Inc()
		},
		SentVersionNegotiationPacket: func(addr net.Addr, _, _ logging.ArbitraryLenConnectionID, _ []logging.Version) {
			tags := getStringSlice()
			defer putStringSlice(tags)

			*tags = append(*tags, getIPVersion(addr))
			*tags = append(*tags, "version_negotiation")
			connsRejected.WithLabelValues(*tags...).Inc()
		},
		DroppedPacket: func(addr net.Addr, pt logging.PacketType, _ logging.ByteCount, reason logging.PacketDropReason) {
			tags := getStringSlice()
			defer putStringSlice(tags)

			var dropReason string
			//nolint:exhaustive // Only a few drop reasons applicable.
			switch reason {
			case logging.PacketDropDOSPrevention:
				if pt == logging.PacketType0RTT {
					dropReason = "0rtt_dos_prevention"
				} else {
					dropReason = "dos_prevention"
				}
			case logging.PacketDropHeaderParseError:
				dropReason = "header_parsing"
			case logging.PacketDropPayloadDecryptError:
				dropReason = "payload_decrypt"
			case logging.PacketDropUnexpectedPacket:
				dropReason = "unexpected_packet"
			default:
				dropReason = "unknown"
			}

			*tags = append(*tags, getIPVersion(addr))
			*tags = append(*tags, dropReason)
			packetDropped.WithLabelValues(*tags...).Inc()
		},
	}
}
