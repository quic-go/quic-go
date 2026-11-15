package simnet

import (
	"encoding/binary"
	"testing"
	"testing/synctest"
	"time"

	"github.com/quic-go/quic-go/internal/protocol"

	"github.com/stretchr/testify/require"
)

func TestCodel(t *testing.T) {
	for _, ecn := range []protocol.ECN{protocol.ECT0, protocol.ECNNon} {
		t.Run(ecn.String(), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				var received []Packet
				router := &testRouter{onSend: func(p Packet) { received = append(received, p) }}
				link := SimulatedLink{
					UplinkSettings: LinkSettings{MTU: 1250, Bandwidth: 10_000_000}, // 1 ms per packet
					UploadPacket:   router,
					downloadPacket: router,
				}
				link.Start()
				for i := range 300 {
					// arrive at twice the link rate
					data := make([]byte, 1250)
					binary.BigEndian.PutUint16(data, uint16(i))
					require.NoError(t, link.SendPacket(Packet{Data: data, ECN: ecn}))
					time.Sleep(time.Millisecond / 2)
				}
				time.Sleep(time.Second)
				require.NoError(t, link.Close())

				var marked, dropped []int
				var next int
				for _, p := range received {
					i := int(binary.BigEndian.Uint16(p.Data))
					for ; next < i; next++ {
						dropped = append(dropped, next)
					}
					next = i + 1
					if p.ECN == protocol.ECNCE {
						marked = append(marked, i)
					}
				}
				require.Equal(t, 300, next)
				// The sojourn time exceeds 5ms at packet 10, which leaves at 10ms.
				// The first signal is one interval later, the next ones follow the control law.
				// Dropped packets don't use the link, so later packets leave earlier.
				if ecn == protocol.ECT0 {
					require.Equal(t, []int{110, 210, 281}, marked)
					require.Empty(t, dropped)
				} else {
					require.Empty(t, marked)
					require.Equal(t, []int{110, 211, 283}, dropped)
				}
			})
		})
	}
}
