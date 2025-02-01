//go:build !gomock && !generate

package mocklogging

import (
	"net"

	"github.com/Noooste/quic-go/internal/mocks/logging/internal"
	"github.com/Noooste/quic-go/logging"

	"go.uber.org/mock/gomock"
)

type MockTracer = internal.MockTracer

func NewMockTracer(ctrl *gomock.Controller) (*logging.Tracer, *MockTracer) {
	t := internal.NewMockTracer(ctrl)
	return &logging.Tracer{
		SentPacket: func(remote net.Addr, hdr *logging.Header, size logging.ByteCount, frames []logging.Frame) {
			t.SentPacket(remote, hdr, size, frames)
		},
		SentVersionNegotiationPacket: func(remote net.Addr, dest, src logging.ArbitraryLenConnectionID, versions []logging.Version) {
			t.SentVersionNegotiationPacket(remote, dest, src, versions)
		},
		DroppedPacket: func(remote net.Addr, typ logging.PacketType, size logging.ByteCount, reason logging.PacketDropReason) {
			t.DroppedPacket(remote, typ, size, reason)
		},
		Debug: func(name, msg string) {
			t.Debug(name, msg)
		},
		Close: func() {
			t.Close()
		},
	}, t
}
