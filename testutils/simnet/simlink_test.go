package simnet

import (
	"fmt"
	"math"
	"net"
	"testing"
	"time"

	"github.com/quic-go/quic-go/internal/synctest"
	"github.com/stretchr/testify/require"
)

type testRouter struct {
	onSend func(p Packet)
	onRecv func(p Packet)
}

func (r *testRouter) SendPacket(p Packet) error {
	r.onSend(p)
	return nil
}

func (r *testRouter) RecvPacket(p Packet) {
	r.onRecv(p)
}

func (r *testRouter) AddNode(addr net.Addr, receiver PacketReceiver) {
	r.onRecv = receiver.RecvPacket
}

func TestLatency(t *testing.T) {
	for _, testUpload := range []bool{true, false} {
		t.Run(fmt.Sprintf("testing upload=%t", testUpload), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				const downlinkLatency = 10 * time.Millisecond
				const MTU = 1400
				linkSettings := LinkSettings{
					MTU: MTU,
				}

				recvStartTimeChan := make(chan time.Time, 1)
				recvStarted := false
				packetHandler := func(p Packet) {
					if !recvStarted {
						recvStarted = true
						recvStartTimeChan <- time.Now()
					}
				}

				router := &testRouter{}
				if testUpload {
					router.onSend = packetHandler
				} else {
					router.onRecv = packetHandler
				}
				link := SimulatedLink{
					UplinkSettings:   linkSettings,
					DownlinkSettings: linkSettings,
					LatencyFunc:      func(p Packet) time.Duration { return downlinkLatency },
					UploadPacket:     router,
					downloadPacket:   router,
				}

				link.Start()

				chunk := make([]byte, MTU)
				sendStartTime := time.Now()
				if testUpload {
					_ = link.SendPacket(Packet{Data: chunk})
				} else {
					link.RecvPacket(Packet{Data: chunk})
				}

				// Wait for delayed packets to be sent
				time.Sleep(40 * time.Millisecond)

				link.Close()
				recvStartTime := <-recvStartTimeChan

				observedLatency := recvStartTime.Sub(sendStartTime)
				// Uplink is now instant (no latency), only downlink has latency
				var expectedLatency time.Duration
				if testUpload {
					// Uplink test: expect near-zero latency
					expectedLatency = 0
					t.Logf("observed latency: %s (uplink is instant)", observedLatency)
					if observedLatency > 5*time.Millisecond {
						t.Fatalf("observed latency %s is too high for instant uplink", observedLatency)
					}
				} else {
					// Downlink test: expect configured latency
					expectedLatency = downlinkLatency
					percentErrorLatency := math.Abs(observedLatency.Seconds()-expectedLatency.Seconds()) / expectedLatency.Seconds()
					t.Logf("observed latency: %s, expected latency: %s, percent error: %f", observedLatency, expectedLatency, percentErrorLatency)
					if percentErrorLatency > 0.20 {
						t.Fatalf("observed latency %s is wrong", observedLatency)
					}
				}
			})
		})
	}
}

func TestMTUEnforcement(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const MTU = 1400
		linkSettings := LinkSettings{
			MTU: MTU,
		}

		packetsReceived := 0
		packetHandler := func(p Packet) {
			packetsReceived++
		}

		router := &testRouter{
			onSend: packetHandler,
			onRecv: packetHandler,
		}
		link := SimulatedLink{
			UplinkSettings:   linkSettings,
			DownlinkSettings: linkSettings,
			UploadPacket:     router,
			downloadPacket:   router,
		}

		link.Start()

		// Send a packet that fits within MTU - should be delivered
		smallPacket := make([]byte, MTU)
		err := link.SendPacket(Packet{Data: smallPacket})
		require.NoError(t, err)

		// Send a packet that exceeds MTU - should be dropped
		largePacket := make([]byte, MTU+1)
		err = link.SendPacket(Packet{Data: largePacket})
		require.NoError(t, err) // SendPacket returns nil even when dropping

		// Receive a packet that fits within MTU - should be delivered
		link.RecvPacket(Packet{Data: smallPacket})

		// Receive a packet that exceeds MTU - should be dropped
		link.RecvPacket(Packet{Data: largePacket})

		// Wait for packets to be processed
		time.Sleep(10 * time.Millisecond)

		link.Close()

		// Only packets within MTU should be received (2 packets: 1 from SendPacket, 1 from RecvPacket)
		if packetsReceived != 2 {
			t.Fatalf("expected 2 packets to be received, got %d", packetsReceived)
		}
	})
}
