package bbr

import (
	"math/rand"
	"time"

	"github.com/lucas-clemente/quic-go/congestion"
	"github.com/lucas-clemente/quic-go/protocol"
	"github.com/lucas-clemente/quic-go/utils"
)

// Mode is the BBR mode
type Mode int

const (
	// Startup phase of the connection.
	Startup Mode = 1 + iota
	// Drain After achieving the highest possible bandwidth during the startup, lower
	// the pacing rate in order to drain the queue.
	Drain
	// ProbeBW After achieving the highest possible bandwidth during the startup, lower
	// the pacing rate in order to drain the queue.
	ProbeBW
	// ProbeRTT Temporarily slow down sending in order to empty the buffer and measure
	// the real minimum RTT.
	ProbeRTT
)

// RecoveryState indicates how the congestion control limits the amount of bytes in flight.
type RecoveryState int

const (
	// NotInRecovery Do not limit.
	NotInRecovery RecoveryState = 1 + iota
	// Conservation Allow an extra outstanding byte for each byte acknowledged.
	Conservation
	// Growth Allow two extra outstanding bytes for each byte acknowledged (slow start)
	Growth
)

// Constants based on TCP defaults.
const maxSegmentSize protocol.ByteCount = protocol.DefaultTCPMSS

// The minimum CWND to ensure delayed acks don't reduce bandwidth measurements.
// Does not inflate the pacing rate.
const minimumCongestionWindow protocol.ByteCount = 4 * maxSegmentSize

// The gain used for the slow start, equal to 2/ln(2).
const highGain float64 = 2.885

// The gain used to drain the queue after the slow start.
const drainGain float64 = 1 / highGain

// The gain used to set the congestion window during most of the modes.
const congestionWindowGain float64 = 2

// The cycle of gains used during the PROBE_BW stage.
var pacingGain = []float64{1.25, 0.75, 1, 1, 1, 1, 1, 1}

// The length of the gain cycle.
const gainCycleLength = 8 // must be equal to len(pacingGain)

// The size of the bandwidth filter window, in round-trips.
const bandwidthWindowSize roundTripCount = gainCycleLength + 2

// The time after which the current min_rtt value expires.
const minRttExpiry = 10 * time.Second

// The minimum time the connection can spend in PROBE_RTT mode.
const probeRttTime = 200 * time.Millisecond

// If the bandwidth does not increase by the factor of |kStartupGrowthTarget|
// within |kRoundTripsWithoutGrowthBeforeExitingStartup| rounds, the connection
// will exit the STARTUP mode.
const startupGrowthTarget float64 = 1.25
const roundTripsWithoutGrowthBeforeExitingStartup roundTripCount = 3

type bbrSender struct {
	rttStats *congestion.RTTStats

	mode Mode

	// Bandwidth sampler provides BBR with the bandwidth measurements at individual points.
	sampler bandwidthSampler
	// The number of the round trips that have occurred during the connection.
	roundTripCount roundTripCount
	// The packet number of the most recently sent packet.
	lastSentPacket protocol.PacketNumber
	// Acknowledgement of any packet after |current_round_trip_end_| will cause
	// the round trip counter to advance.
	currentRoundTripEnd protocol.PacketNumber
	// The filter that tracks the maximum bandwidth over the multiple recent round-trips.
	maxBandwidth windowedFilter
	// Minimum RTT estimate.  Automatically expires within 10 seconds (and
	// triggers PROBE_RTT mode) if no new value is sampled during that period.
	minRtt time.Duration
	// The time at which the current value of |min_rtt_| was assigned.
	minRttTimestamp time.Time

	// The maximum allowed number of bytes in flight.
	congestionWindow protocol.ByteCount
	// The initial value of the |congestion_window_|.
	initialCongestionWindow protocol.ByteCount
	// The largest value the |congestion_window_| can achieve.
	maxCongestionWindow protocol.ByteCount
	// The current pacing rate of the connection.
	pacingRateValue protocol.Bandwidth

	// The gain currently applied to the pacing rate.
	pacingGain float64
	// The gain currently applied to the congestion window.
	congestionWindowGain float64

	// Number of round-trips in PROBE_BW mode, used for determining the current
	// pacing gain cycle.
	cycleCurrentOffset int
	// The time at which the last pacing gain cycle was started.
	lastCycleStart time.Time

	// Indicates whether the connection has reached the full bandwidth mode.
	isAtFullBandwidth bool
	// Number of rounds during which there was no significant bandwidth increase.
	roundsWithoutBandwidthGain roundTripCount
	// The bandwidth compared to which the increase is measured.
	bandwidthAtLastRound protocol.Bandwidth

	// Set to true upon exiting quiescence.
	exitingQuiescence bool

	// Time at which PROBE_RTT has to be exited.  Setting it to zero indicates
	// that the time is yet unknown as the number of packets in flight has not
	// reached the required value.
	exitProbeRttAt time.Time
	// Indicates whether a round-trip has passed since PROBE_RTT became active.
	probeRttRoundPassed bool

	// Indicates whether the most recent bandwidth sample was marked as
	// app-limited.
	lastSampleIsAppLimited bool

	// Current state of recovery.
	recoveryState RecoveryState
	// Receiving acknowledgement of a packet after |end_recovery_at_| will cause
	// BBR to exit the recovery mode.
	endRecoveryAt protocol.PacketNumber
	// A window used to limit the number of bytes in flight during loss recovery.
	recoveryWindow protocol.ByteCount
}

var _ congestion.SendAlgorithm = &bbrSender{}

func (b *bbrSender) TimeUntilSend(now time.Time, bytesInFlight protocol.ByteCount) time.Duration {
	if bytesInFlight < b.GetCongestionWindow() {
		return time.Duration(0)
	}
	return utils.InfDuration
}

func (b *bbrSender) pacingRate(_ protocol.ByteCount /*bytes in flight*/) protocol.Bandwidth {
	if b.pacingRateValue == 0 {
		return protocol.Bandwidth(highGain * float64(protocol.BandwidthFromDelta(b.initialCongestionWindow, b.getMinRtt())))
	}
	return b.pacingRateValue
}

func (b *bbrSender) bandwidthEstimate() protocol.Bandwidth {
	return b.maxBandwidth.GetBest()
}

func (b *bbrSender) OnPacketSent(sentTime time.Time, bytesInFlight protocol.ByteCount, packetNumber protocol.PacketNumber, bytes protocol.ByteCount, isRetransmittable bool) bool {
	b.lastSentPacket = packetNumber

	if bytesInFlight == 0 && b.sampler.isAppLimited {
		b.exitingQuiescence = true
	}

	b.sampler.OnPacketSent(sentTime, packetNumber, bytes, bytesInFlight, isRetransmittable)
	return isRetransmittable
}

func (b *bbrSender) GetCongestionWindow() protocol.ByteCount {
	if b.mode == ProbeRTT {
		return minimumCongestionWindow
	}

	if b.inRecovery() {
		return utils.MinByteCount(b.congestionWindow, b.recoveryWindow)
	}

	return b.congestionWindow
}

func (b *bbrSender) OnCongestionEvent(_ bool /* rtt updated */, priorInFlight, bytesInFlight protocol.ByteCount, eventTime time.Time, ackedPackets congestion.PacketVector, lostPackets congestion.PacketVector, leastUnacked protocol.PacketNumber) {
	totalBytesAckedBefore := b.sampler.totalBytesAcked

	var isRoundStart bool
	var minRttExpired bool

	b.discardLostPackets(lostPackets)

	hasLostPackets := (len(lostPackets) != 0)

	// Input the new data into the BBR model of the connection.
	if len(ackedPackets) != 0 {
		lastAckedPacket := ackedPackets[0].Number
		isRoundStart = b.updateRoundTripCounter(lastAckedPacket)
		minRttExpired = b.updateBandwidthAndMinRtt(eventTime, ackedPackets)
		b.updateRecoveryState(lastAckedPacket, hasLostPackets, isRoundStart)
	}

	// Handle logic specific to PROBE_BW mode.
	if b.mode == ProbeBW {
		b.updateGainCyclePhase(eventTime, priorInFlight, hasLostPackets)
	}

	// Handle logic specific to STARTUP and DRAIN modes.
	if isRoundStart && !b.isAtFullBandwidth {
		b.checkIfFullBandwidthReached()
	}
	b.maybeExitStartupOrDrain(eventTime, bytesInFlight)

	// Handle logic specific to PROBE_RTT.
	b.maybeEnterOrExitProbeRtt(eventTime, isRoundStart, minRttExpired, bytesInFlight)

	// After the model is updated, recalculate the pacing rate and congestion window.
	bytesAcked := b.sampler.totalBytesAcked - totalBytesAckedBefore
	b.calculatePacingRate()
	b.calculateCongestionWindow(bytesAcked)
	b.calculateRecoveryWindow(bytesAcked, bytesInFlight)

	// Cleanup internal state.
	b.sampler.RemoveObsoletePackets(leastUnacked)
}

func (b *bbrSender) SetNumEmulatedConnections(n int) {

}

func (b *bbrSender) OnRetransmissionTimeout(packetsRetransmitted bool) {

}

func (b *bbrSender) OnConnectionMigration() {

}

func (b *bbrSender) RetransmissionDelay() time.Duration {
	return time.Millisecond
}

// Experiments
func (b *bbrSender) SetSlowStartLargeReduction(enabled bool) {
}

func (b *bbrSender) inSlowStart() bool {
	return b.mode == Startup
}

func (b *bbrSender) inRecovery() bool {
	return b.recoveryState != NotInRecovery
}

func (b *bbrSender) getMinRtt() time.Duration {
	if b.minRtt != 0 {
		return b.minRtt
	}
	return time.Duration(b.rttStats.InitialRTTus()) * time.Microsecond
}

func (b *bbrSender) discardLostPackets(lostPackets congestion.PacketVector) {
	for _, packet := range lostPackets {
		b.sampler.OnPacketLost(packet.Number)
	}
}

func (b *bbrSender) updateRoundTripCounter(lastAckedPacket protocol.PacketNumber) bool {
	if lastAckedPacket > b.currentRoundTripEnd {
		b.roundTripCount++
		b.currentRoundTripEnd = b.lastSentPacket
		return true
	}
	return false
}

func (b *bbrSender) updateBandwidthAndMinRtt(now time.Time, ackedPackets congestion.PacketVector) bool {
	sampleMinRtt := utils.InfDuration
	for _, packet := range ackedPackets {
		bandwidthSample := b.sampler.OnPacketAcknowledged(now, packet.Number)
		b.lastSampleIsAppLimited = bandwidthSample.isAppLimited
		if bandwidthSample.rtt != 0 {
			sampleMinRtt = utils.MinDuration(sampleMinRtt, bandwidthSample.rtt)
		}
		if !bandwidthSample.isAppLimited || bandwidthSample.bandwidth > b.bandwidthEstimate() {
			b.maxBandwidth.Update(bandwidthSample.bandwidth, b.roundTripCount)
		}
	}

	// If none of the RTT samples are valid, return immediately.
	if sampleMinRtt == utils.InfDuration {
		return false
	}

	// Do not expire min_rtt if none was ever available.
	minRttExpired := (b.minRtt != 0 && now.After(b.minRttTimestamp.Add(minRttExpiry)))
	if minRttExpired || sampleMinRtt < b.minRtt || b.minRtt == 0 {
		b.minRtt = sampleMinRtt
		b.minRttTimestamp = now
	}

	return minRttExpired
}

func (b *bbrSender) updateRecoveryState(lastAckedPacket protocol.PacketNumber, hasLosses, isRoundStart bool) {
	// Exit recovery when there are no losses for a round.
	if hasLosses {
		b.endRecoveryAt = b.lastSentPacket
	}

	switch b.recoveryState {
	case NotInRecovery:
		// Enter conservation on the first loss.
		if hasLosses {
			b.recoveryState = Conservation
			// Since the conservation phase is meant to be lasting for a whole
			// round, extend the current round as if it were started right now.
			b.currentRoundTripEnd = b.lastSentPacket
		}
	case Conservation:
		if isRoundStart {
			b.recoveryState = Growth
		}
	case Growth:
		// Exit recovery if appropriate.
		if !hasLosses && lastAckedPacket > b.endRecoveryAt {
			b.recoveryState = NotInRecovery
		}
	}
}

func (b *bbrSender) updateGainCyclePhase(now time.Time, priorInFlight protocol.ByteCount, hasLosses bool) {
	// In most cases, the cycle is advanced after an RTT passes.
	shouldAdvanceGainCycling := (now.Sub(b.lastCycleStart) > b.getMinRtt())

	// If the pacing gain is above 1.0, the connection is trying to probe the
	// bandwidth by increasing the number of bytes in flight to at least
	// pacing_gain * BDP.  Make sure that it actually reaches the target, as long
	// as there are no losses suggesting that the buffers are not able to hold
	// that much.
	if b.pacingGain > 1 && !hasLosses && priorInFlight < b.getTargetCongestionWindow(b.pacingGain) {
		shouldAdvanceGainCycling = false
	}

	// If pacing gain is below 1.0, the connection is trying to drain the extra
	// queue which could have been incurred by probing prior to it.  If the number
	// of bytes in flight falls down to the estimated BDP value earlier, conclude
	// that the queue has been successfully drained and exit this cycle early.
	if b.pacingGain < 1 && priorInFlight < b.getTargetCongestionWindow(1) {
		shouldAdvanceGainCycling = true
	}

	if shouldAdvanceGainCycling {
		b.cycleCurrentOffset = (b.cycleCurrentOffset + 1) % gainCycleLength
		b.lastCycleStart = now
		b.pacingGain = pacingGain[b.cycleCurrentOffset]
	}
}

func (b *bbrSender) getTargetCongestionWindow(gain float64) protocol.ByteCount {
	bdp := b.getMinRtt().Seconds() * float64(b.bandwidthEstimate()/protocol.BytesPerSecond)
	congestionWindow := protocol.ByteCount(gain * float64(bdp))

	// BDP estimate will be zero if no bandwidth samples are available yet.
	if congestionWindow == 0 {
		congestionWindow = protocol.ByteCount(gain * float64(b.initialCongestionWindow))
	}

	return utils.MaxByteCount(congestionWindow, minimumCongestionWindow)
}

func (b *bbrSender) checkIfFullBandwidthReached() {
	if b.lastSampleIsAppLimited {
		return
	}

	target := protocol.Bandwidth(float64(b.bandwidthAtLastRound) * startupGrowthTarget)
	if b.bandwidthEstimate() >= target {
		b.bandwidthAtLastRound = b.bandwidthEstimate()
		b.roundsWithoutBandwidthGain = 0
		return
	}

	b.roundsWithoutBandwidthGain++
	if b.roundsWithoutBandwidthGain >= roundTripsWithoutGrowthBeforeExitingStartup {
		b.isAtFullBandwidth = true
	}
}

func (b *bbrSender) maybeExitStartupOrDrain(now time.Time, bytesInFlight protocol.ByteCount) {
	if b.mode == Startup && b.isAtFullBandwidth {
		b.mode = Drain
		b.pacingGain = drainGain
		b.congestionWindowGain = highGain
	}
	if b.mode == Drain && bytesInFlight <= b.getTargetCongestionWindow(1) {
		b.enterProbeBandwidthMode(now)
	}
}

func (b *bbrSender) enterStartupMode() {
	b.mode = Startup
	b.pacingGain = highGain
	b.congestionWindowGain = highGain
}

func (b *bbrSender) enterProbeBandwidthMode(now time.Time) {
	b.mode = ProbeBW
	b.congestionWindowGain = congestionWindowGain

	// Pick a random offset for the gain cycle out of {0, 2..7} range. 1 is
	// excluded because in that case increased gain and decreased gain would not
	// follow each other.
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	b.cycleCurrentOffset = int(r.Uint32() % (gainCycleLength - 1))
	if b.cycleCurrentOffset >= 1 {
		b.cycleCurrentOffset++
	}

	b.lastCycleStart = now
	b.pacingGain = pacingGain[b.cycleCurrentOffset]
}

func (b *bbrSender) maybeEnterOrExitProbeRtt(now time.Time, isRoundStart, minRttExpired bool, bytesInFlight protocol.ByteCount) {
	if minRttExpired && !b.exitingQuiescence && b.mode != ProbeRTT {
		b.mode = ProbeRTT
		b.pacingGain = 1
		// Do not decide on the time to exit PROBE_RTT until the |bytes_in_flight|
		// is at the target small value.
		b.exitProbeRttAt = time.Time{}
	}

	if b.mode == ProbeRTT {
		b.sampler.OnAppLimited()

		if b.exitProbeRttAt.IsZero() {
			// If the window has reached the appropriate size, schedule exiting
			// PROBE_RTT.  The CWND during PROBE_RTT is kMinimumCongestionWindow, but
			// we allow an extra packet since QUIC checks CWND before sending a packet.
			if bytesInFlight < minimumCongestionWindow+protocol.MaxPacketSize {
				b.exitProbeRttAt = now.Add(probeRttTime)
				b.probeRttRoundPassed = false
			}
		} else {
			if isRoundStart {
				b.probeRttRoundPassed = true
			}
			if !now.Before(b.exitProbeRttAt) && b.probeRttRoundPassed {
				b.minRttTimestamp = now
				if !b.isAtFullBandwidth {
					b.enterStartupMode()
				} else {
					b.enterProbeBandwidthMode(now)
				}
			}
		}
	}
}

func (b *bbrSender) calculatePacingRate() {
	if b.bandwidthEstimate() == 0 {
		return
	}

	b.pacingRateValue = protocol.Bandwidth(b.pacingGain * float64(b.bandwidthEstimate()))
}

func (b *bbrSender) calculateRecoveryWindow(bytesAcked, bytesInFlight protocol.ByteCount) {
	switch b.recoveryState {
	case Conservation:
		b.recoveryWindow = bytesInFlight + bytesAcked
	case Growth:
		b.recoveryWindow = bytesInFlight + 2*bytesAcked
	}
	b.recoveryWindow = utils.MaxByteCount(b.recoveryWindow, minimumCongestionWindow)
}

func (b *bbrSender) calculateCongestionWindow(bytesAcked protocol.ByteCount) {
	if b.mode == ProbeRTT {
		return
	}

	targetWindow := b.getTargetCongestionWindow(b.congestionWindowGain)

	// Instead of immediately setting the target CWND as the new one, BBR grows
	// the CWND towards |target_window| by only increasing it |bytes_acked| at a time.
	if b.isAtFullBandwidth {
		// If the connection is not yet out of startup phase, do not decrease the window.
		b.congestionWindow = utils.MinByteCount(targetWindow, b.congestionWindow+bytesAcked)
	} else if b.congestionWindow < targetWindow || b.sampler.totalBytesAcked < b.initialCongestionWindow {
		b.congestionWindow += bytesAcked
	}

	// Enforce the limits on the congestion window.
	b.congestionWindow = utils.MaxByteCount(b.congestionWindow, minimumCongestionWindow)
	b.congestionWindow = utils.MinByteCount(b.congestionWindow, b.maxCongestionWindow)
}

func (b *bbrSender) onApplicationLimited(bytesInFlight protocol.ByteCount) {
	if bytesInFlight >= b.GetCongestionWindow() {
		return
	}

	b.sampler.OnAppLimited()
}
