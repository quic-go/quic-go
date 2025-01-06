package quic

import (
	"testing"

	"github.com/quic-go/quic-go/internal/wire"
	"github.com/quic-go/quic-go/logging"

	"github.com/stretchr/testify/require"
)

func TestConnectionLoggingCryptoFrame(t *testing.T) {
	f := toLoggingFrame(&wire.CryptoFrame{
		Offset: 1234,
		Data:   []byte("foobar"),
	})
	require.Equal(t, &logging.CryptoFrame{
		Offset: 1234,
		Length: 6,
	}, f)
}

func TestConnectionLoggingStreamFrame(t *testing.T) {
	f := toLoggingFrame(&wire.StreamFrame{
		StreamID: 42,
		Offset:   1234,
		Data:     []byte("foo"),
		Fin:      true,
	})
	require.Equal(t, &logging.StreamFrame{
		StreamID: 42,
		Offset:   1234,
		Length:   3,
		Fin:      true,
	}, f)
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
	f := toLoggingFrame(ack)
	// now modify the ACK range in the original frame
	ack.AckRanges[0].Smallest = 2
	require.Equal(t, &logging.AckFrame{
		AckRanges: []wire.AckRange{
			{Smallest: 1, Largest: 3}, // unchanged, since the ACK ranges were cloned
			{Smallest: 6, Largest: 7},
		},
		DelayTime: 42,
		ECNCE:     123,
		ECT0:      456,
		ECT1:      789,
	}, f)
}

func TestConnectionLoggingDatagramFrame(t *testing.T) {
	f := toLoggingFrame(&wire.DatagramFrame{Data: []byte("foobar")})
	require.Equal(t, &logging.DatagramFrame{Length: 6}, f)
}

func TestConnectionLoggingOtherFrames(t *testing.T) {
	f := toLoggingFrame(&wire.MaxDataFrame{MaximumData: 1234})
	require.Equal(t, &logging.MaxDataFrame{MaximumData: 1234}, f)
}
