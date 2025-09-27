package qlogevents

import (
	"io"
	"net"

	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/logging"
	"github.com/quic-go/quic-go/qlog"
)

func NewTracer(w io.WriteCloser) *logging.Tracer {
	tr := qlog.NewFileSeq(w)
	go tr.Run()

	wr := tr.AddProducer()
	return &logging.Tracer{
		SentPacket: func(_ net.Addr, hdr *logging.Header, size logging.ByteCount, frames []logging.Frame) {
			fs := make([]frame, 0, len(frames))
			for _, f := range frames {
				fs = append(fs, frame{Frame: f})
			}
			wr.RecordEvent(&eventPacketSent{
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
			wr.RecordEvent(&eventVersionNegotiationSent{
				Header: packetHeaderVersionNegotiation{
					SrcConnectionID:  src,
					DestConnectionID: dest,
				},
				SupportedVersions: ver,
			})
		},
		DroppedPacket: func(addr net.Addr, p logging.PacketType, count logging.ByteCount, reason logging.PacketDropReason) {
			wr.RecordEvent(eventPacketDropped{
				PacketType:   p,
				PacketNumber: protocol.InvalidPacketNumber,
				PacketSize:   count,
				Trigger:      packetDropReason(reason),
			})
		},
		Debug: func(name, msg string) {
			wr.RecordEvent(&eventGeneric{
				name: name,
				msg:  msg,
			})
		},
		Close: func() { wr.Close() },
	}
}
