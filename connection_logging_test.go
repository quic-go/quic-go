package quic

import (
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
