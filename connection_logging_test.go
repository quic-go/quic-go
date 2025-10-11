package quic

import (
	"net"
	"net/netip"
	"testing"

	"github.com/quic-go/quic-go/internal/wire"
	"github.com/quic-go/quic-go/qlog"

	"github.com/stretchr/testify/require"
)

func TestConnectionLoggingCryptoFrame(t *testing.T) {
	f := toQlogFrame(&wire.CryptoFrame{
		Offset: 1234,
		Data:   []byte("foobar"),
	})
	require.Equal(t, &qlog.CryptoFrame{
		Offset: 1234,
		Length: 6,
	}, f.Frame)
}

func TestConnectionLoggingStreamFrame(t *testing.T) {
	f := toQlogFrame(&wire.StreamFrame{
		StreamID: 42,
		Offset:   1234,
		Data:     []byte("foo"),
		Fin:      true,
	})
	require.Equal(t, &qlog.StreamFrame{
		StreamID: 42,
		Offset:   1234,
		Length:   3,
		Fin:      true,
	}, f.Frame)
}

func TestConnectionLoggingAckFrame(t *testing.T) {
	ack := &wire.AckFrame{
		AckRanges: []wire.AckRange{
			{Smallest: 1, Largest: 3},
			{Smallest: 6, Largest: 7},
		},
		DelayTime: 42,
		ECNCE:     123,
		ECT0:      456,
		ECT1:      789,
	}
	f := toQlogFrame(ack)
	// now modify the ACK range in the original frame
	ack.AckRanges[0].Smallest = 2
	require.Equal(t, &qlog.AckFrame{
		AckRanges: []wire.AckRange{
			{Smallest: 1, Largest: 3}, // unchanged, since the ACK ranges were cloned
			{Smallest: 6, Largest: 7},
		},
		DelayTime: 42,
		ECNCE:     123,
		ECT0:      456,
		ECT1:      789,
	}, f.Frame)
}

func TestConnectionLoggingDatagramFrame(t *testing.T) {
	f := toQlogFrame(&wire.DatagramFrame{Data: []byte("foobar")})
	require.Equal(t, &qlog.DatagramFrame{Length: 6}, f.Frame)
}

func TestConnectionLoggingOtherFrames(t *testing.T) {
	f := toQlogFrame(&wire.MaxDataFrame{MaximumData: 1234})
	require.Equal(t, &qlog.MaxDataFrame{MaximumData: 1234}, f.Frame)
}

func TestConnectionLoggingStartedConnectionEvent(t *testing.T) {
	tests := []struct {
		name          string
		local         *net.UDPAddr
		remote        *net.UDPAddr
		wantLocalIP   string
		wantLocalPort uint16
		wantRemote    netip.AddrPort
	}{
		{
			name:          "unspecified local, remote IPv4 -> 0.0.0.0",
			local:         &net.UDPAddr{Port: 58451},
			remote:        &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 6121},
			wantLocalIP:   "0.0.0.0",
			wantLocalPort: 58451,
			wantRemote:    netip.AddrPortFrom(netip.AddrFrom4([4]byte{127, 0, 0, 1}), 6121),
		},
		{
			name:          "unspecified local, remote IPv6 -> ::",
			local:         &net.UDPAddr{Port: 4242},
			remote:        &net.UDPAddr{IP: net.ParseIP("2001:db8::1"), Port: 6121},
			wantLocalIP:   "::",
			wantLocalPort: 4242,
			wantRemote:    func() netip.AddrPort { a, _ := netip.ParseAddr("2001:db8::1"); return netip.AddrPortFrom(a, 6121) }(),
		},
		{
			name:          "specified local IPv4",
			local:         &net.UDPAddr{IP: net.IPv4(192, 168, 1, 10), Port: 9999},
			remote:        &net.UDPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 1234},
			wantLocalIP:   "192.168.1.10",
			wantLocalPort: 9999,
			wantRemote:    netip.AddrPortFrom(netip.AddrFrom4([4]byte{10, 0, 0, 1}), 1234),
		},
		{
			name:          "specified local IPv6",
			local:         &net.UDPAddr{IP: net.ParseIP("fe80::1"), Port: 999},
			remote:        &net.UDPAddr{IP: net.ParseIP("2001:db8::1"), Port: 6121},
			wantLocalIP:   "fe80::1",
			wantLocalPort: 999,
			wantRemote:    func() netip.AddrPort { a, _ := netip.ParseAddr("2001:db8::1"); return netip.AddrPortFrom(a, 6121) }(),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ev := startedConnectionEvent(tc.local, tc.remote)
			var gotIP string
			var gotPort uint16
			if ev.Local.IPv4.IsValid() {
				gotIP = ev.Local.IPv4.Addr().String()
				gotPort = ev.Local.IPv4.Port()
			} else if ev.Local.IPv6.IsValid() {
				gotIP = ev.Local.IPv6.Addr().String()
				gotPort = ev.Local.IPv6.Port()
			}
			require.Equal(t, tc.wantLocalIP, gotIP)
			require.Equal(t, tc.wantLocalPort, gotPort)

			var gotRemote netip.AddrPort
			if ev.Remote.IPv4.IsValid() {
				gotRemote = ev.Remote.IPv4
			} else if ev.Remote.IPv6.IsValid() {
				gotRemote = ev.Remote.IPv6
			}
			require.Equal(t, tc.wantRemote, gotRemote)
		})
	}
}
