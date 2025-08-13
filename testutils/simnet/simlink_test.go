//go:build goexperiment.synctest

package simnet

import (
	"fmt"
	"math"
	"net"
	"testing"
	"testing/synctest"
	"time"
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

const Mibps = 1_000_000

func TestBandwidthLimiterAndLatency_synctest(t *testing.T) {
	synctest.Run(func() {
		for _, testUpload := range []bool{true, false} {
			t.Run(fmt.Sprintf("testing upload=%t", testUpload), func(t *testing.T) {
				const expectedSpeed = 10 * Mibps
				const expectedLatency = 10 * time.Millisecond
				const MTU = 1400
				linkSettings := LinkSettings{
					BitsPerSecond: expectedSpeed,
					MTU:           MTU,
					Latency:       expectedLatency,
				}

				recvStartTimeChan := make(chan time.Time, 1)
				recvStarted := false
				bytesRead := 0
				packetHandler := func(p Packet) {
					if !recvStarted {
						recvStarted = true
						recvStartTimeChan <- time.Now()
					}
					bytesRead += len(p.buf)
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
					UploadPacket:     router,
					downloadPacket:   router,
				}

				link.Start()

				// Send 10MiB of data
				chunk := make([]byte, MTU)
				bytesSent := 0

				sendStartTime := time.Now()
				{
					totalBytes := 10 << 20
					// Blast a bunch of packets
					for bytesSent < totalBytes {
						// This sleep shouldn't limit the speed. 1400 Bytes/100us = 14KB/ms = 14MB/s = 14*8 Mbps
						// but it acts as a simple pacer to avoid just dropping the packets when the link is saturated.
						time.Sleep(100 * time.Microsecond)
						if testUpload {
							_ = link.SendPacket(Packet{buf: chunk})
						} else {
							link.RecvPacket(Packet{buf: chunk})
						}
						bytesSent += len(chunk)
					}
				}

				// Wait for delayed packets to be sent
				time.Sleep(40 * time.Millisecond)
				fmt.Printf("sent: %d\n", bytesSent)

				link.Close()
				fmt.Printf("bytesRead: %d\n", bytesRead)
				recvStartTime := <-recvStartTimeChan
				duration := time.Since(recvStartTime)

				observedLatency := recvStartTime.Sub(sendStartTime)
				percentErrorLatency := math.Abs(observedLatency.Seconds()-expectedLatency.Seconds()) / expectedLatency.Seconds()
				t.Logf("observed latency: %s, expected latency: %s, percent error: %f\n", observedLatency, expectedLatency, percentErrorLatency)
				if percentErrorLatency > 0.20 {
					t.Fatalf("observed latency %s is wrong", observedLatency)
				}

				observedSpeed := 8 * float64(bytesRead) / duration.Seconds()
				t.Logf("observed speed: %f Mbps over %s\n", observedSpeed/Mibps, duration)
				percentErrorSpeed := math.Abs(observedSpeed-float64(expectedSpeed)) / float64(expectedSpeed)
				t.Logf("observed speed: %f Mbps, expected speed: %d Mbps, percent error: %f\n", observedSpeed/Mibps, expectedSpeed/Mibps, percentErrorSpeed)
				if percentErrorSpeed > 0.20 {
					t.Fatalf("observed speed %f Mbps is too far from expected speed %d Mbps. Percent error: %f", observedSpeed/Mibps, expectedSpeed/Mibps, percentErrorSpeed)
				}
			})
		}
	})
}

type linkAdapter struct {
	link PacketReceiver
}

var _ Router = &linkAdapter{}

// AddNode implements Router.
func (c *linkAdapter) AddNode(addr net.Addr, receiver PacketReceiver) {
	c.link = receiver
}

// SendPacket implements Router.
func (c *linkAdapter) SendPacket(p Packet) error {
	c.link.RecvPacket(p)
	return nil
}

func TestBandwidthLimiterAndLatencyConnectedLinks_synctest(t *testing.T) {
	synctest.Run(func() {
		const expectedSpeed = 100 * Mibps
		const latencyOfOneLink = 10 * time.Millisecond
		const expectedLatency = 2 * latencyOfOneLink
		const MTU = 1400
		linkSettings := LinkSettings{
			BitsPerSecond: expectedSpeed,
			MTU:           MTU,
			Latency:       latencyOfOneLink,
		}

		recvStartTimeChan := make(chan time.Time, 1)
		recvStarted := false
		bytesRead := 0
		packetHandler := func(p Packet) {
			if !recvStarted {
				recvStarted = true
				recvStartTimeChan <- time.Now()
			}
			bytesRead += len(p.buf)
		}
		r := &testRouter{
			onRecv: packetHandler,
		}

		link2 := SimulatedLink{
			UplinkSettings:   linkSettings,
			DownlinkSettings: linkSettings,
			downloadPacket:   r,
		}
		link1 := SimulatedLink{
			UplinkSettings:   linkSettings,
			DownlinkSettings: linkSettings,
			UploadPacket:     &linkAdapter{link: &link2},
			downloadPacket:   &testRouter{},
		}

		link1.Start()
		link2.Start()

		// Send 10MiB of data
		chunk := make([]byte, MTU)
		bytesSent := 0

		sendStartTime := time.Now()
		{
			totalBytes := 10 << 20
			// Blast a bunch of packets
			for bytesSent < totalBytes {
				time.Sleep(100 * time.Microsecond)
				_ = link1.SendPacket(Packet{buf: chunk})
				bytesSent += len(chunk)
			}
		}

		// Wait for delayed packets to be sent
		time.Sleep(40 * time.Millisecond)
		fmt.Printf("sent: %d\n", bytesSent)

		link1.Close()
		link2.Close()
		fmt.Printf("bytesRead: %d\n", bytesRead)
		recvStartTime := <-recvStartTimeChan
		duration := time.Since(recvStartTime)

		observedLatency := recvStartTime.Sub(sendStartTime)
		percentErrorLatency := math.Abs(observedLatency.Seconds()-expectedLatency.Seconds()) / expectedLatency.Seconds()
		t.Logf("observed latency: %s, expected latency: %s, percent error: %f\n", observedLatency, expectedLatency, percentErrorLatency)
		if percentErrorLatency > 0.20 {
			t.Fatalf("observed latency %s is wrong", observedLatency)
		}

		observedSpeed := 8 * float64(bytesRead) / duration.Seconds()
		t.Logf("observed speed: %f Mbps over %s\n", observedSpeed/Mibps, duration)
		percentErrorSpeed := math.Abs(observedSpeed-float64(expectedSpeed)) / float64(expectedSpeed)
		t.Logf("observed speed: %f Mbps, expected speed: %d Mbps, percent error: %f\n", observedSpeed/Mibps, expectedSpeed/Mibps, percentErrorSpeed)
		if percentErrorSpeed > 0.20 {
			t.Fatalf("observed speed %f Mbps is too far from expected speed %d Mbps. Percent error: %f", observedSpeed/Mibps, expectedSpeed/Mibps, percentErrorSpeed)
		}
	})
}
