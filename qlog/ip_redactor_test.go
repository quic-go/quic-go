package qlog

import (
	"context"
	"net/netip"
	"testing"

	"github.com/quic-go/quic-go/qlogwriter"
	"github.com/quic-go/quic-go/testutils/events"

	"github.com/stretchr/testify/require"
)

func TestRedactIPs(t *testing.T) {
	addr4 := netip.MustParseAddrPort("192.0.2.1:443")
	addr6 := netip.MustParseAddrPort("[2001:db8::1]:8443")
	var recorder events.Recorder
	tracer := RedactIPs(
		func(context.Context, bool, ConnectionID) qlogwriter.Trace {
			return &events.Trace{Recorder: &recorder}
		},
		func(_ netip.AddrPort, isLocal bool) (string, bool) {
			return "***", !isLocal
		},
	)
	producer := tracer(context.Background(), true, ConnectionID{}).AddProducer()
	preferred := &PreferredAddress{
		IPv4: addr4,
		IPv6: addr6,
	}

	producer.RecordEvent(StartedConnection{
		Local:  PathEndpointInfo{IPv4: addr4},
		Remote: PathEndpointInfo{IPv6: addr6},
	})
	producer.RecordEvent(ParametersSet{
		Initiator:        InitiatorLocal,
		PreferredAddress: preferred,
	})
	producer.RecordEvent(ParametersSet{
		Initiator:        InitiatorRemote,
		PreferredAddress: preferred,
	})
	mtu := MTUUpdated{Value: 1400}
	producer.RecordEvent(mtu)

	require.Equal(t, []qlogwriter.Event{
		StartedConnection{
			Local:          PathEndpointInfo{IPv4: addr4},
			Remote:         PathEndpointInfo{IPv6: addr6},
			RedactedRemote: new("***"),
		},
		ParametersSet{
			Initiator: InitiatorLocal,
			PreferredAddress: &PreferredAddress{
				IPv4: addr4,
				IPv6: addr6,
			},
		},
		ParametersSet{
			Initiator: InitiatorRemote,
			PreferredAddress: &PreferredAddress{
				IPv4:         addr4,
				IPv6:         addr6,
				RedactedIPv4: new("***"),
				RedactedIPv6: new("***"),
			},
		},
		mtu,
	}, recorder.Events())
	require.Nil(t, preferred.RedactedIPv4)
	require.Nil(t, preferred.RedactedIPv6)
	require.NoError(t, producer.Close())
}
