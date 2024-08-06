package qlog

import (
	"io"
	"net"
	"time"

	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/logging"
)

func NewTracer(w io.WriteCloser) *logging.Tracer {
	tr := &trace{
		VantagePoint: vantagePoint{Type: "transport"},
		CommonFields: commonFields{ReferenceTime: time.Now()},
	}
	wr := *newWriter(w, tr)
	go wr.Run()
	return &logging.Tracer{
		SentPacket: func(_ net.Addr, hdr *logging.Header, size logging.ByteCount, frames []logging.Frame) {
			fs := make([]frame, 0, len(frames))
			for _, f := range frames {
				fs = append(fs, frame{Frame: f})
			}
			wr.RecordEvent(time.Now(), &eventPacketSent{
				Header: transformHeader(hdr),
				Length: size,
				Frames: fs,
			})
		},
		SentVersionNegotiationPacket: func(_ net.Addr, dest, src logging.ArbitraryLenConnectionID, versions []logging.Version) {
			ver := make([]version, len(versions))
			for i, v := range versions {
				ver[i] = version(v)
			}
			wr.RecordEvent(time.Now(), &eventVersionNegotiationSent{
				Header: packetHeaderVersionNegotiation{
					SrcConnectionID:  src,
					DestConnectionID: dest,
				},
				SupportedVersions: ver,
			})
		},
		DroppedPacket: func(addr net.Addr, p logging.PacketType, count logging.ByteCount, reason logging.PacketDropReason) {
			wr.RecordEvent(time.Now(), eventPacketDropped{
				PacketType:   p,
				PacketNumber: protocol.InvalidPacketNumber,
				PacketSize:   count,
				Trigger:      packetDropReason(reason),
			})
		},
		Debug: func(name, msg string) {
			wr.RecordEvent(time.Now(), &eventGeneric{
				name: name,
				msg:  msg,
			})
		},
		Close: func() { wr.Close() },
	}
}
