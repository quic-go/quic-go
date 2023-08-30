package congestion

import (
	"fmt"
	"time"

	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/utils"
	"github.com/quic-go/quic-go/logging"
)

// BbrSender implements BBR congestion control algorithm.  BBR aims to estimate
// the current available Bottleneck Bandwidth and RTT (hence the name), and
// regulates the pacing rate and the size of the congestion window based on
// those signals.
//
// BBR relies on pacing in order to function properly.  Do not use BBR when
// pacing is disabled.
//

const (
	// Constants based on TCP defaults.
	// The minimum CWND to ensure delayed acks don't reduce bandwidth measurements.
	// Does not inflate the pacing rate.
	defaultMinimumCongestionWindow = 4 * protocol.ByteCount(protocol.InitialPacketSizeIPv4)

	// The gain used for the STARTUP, equal to 2/ln(2).
	defaultHighGain = 2.885
	// The newly derived gain for STARTUP, equal to 4 * ln(2)
	derivedHighGain = 2.773
	// The newly derived CWND gain for STARTUP, 2.
	derivedHighCWNDGain = 2.0
)

// The cycle of gains used during the PROBE_BW stage.
var pacingGain = [...]float64{1.25, 0.75, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0}

const (
	// The length of the gain cycle.
	gainCycleLength = len(pacingGain)
	// The size of the bandwidth filter window, in round-trips.
	bandwidthWindowSize = gainCycleLength + 2

	// The time after which the current min_rtt value expires.
	minRttExpiry = 10 * time.Second
	// The minimum time the connection can spend in PROBE_RTT mode.
	probeRttTime = 200 * time.Millisecond
	// If the bandwidth does not increase by the factor of |kStartupGrowthTarget|
	// within |kRoundTripsWithoutGrowthBeforeExitingStartup| rounds, the connection
	// will exit the STARTUP mode.
	startupGrowthTarget                         = 1.25
	roundTripsWithoutGrowthBeforeExitingStartup = int64(3)

	// Flag.
	defaultStartupFullLossCount  = 8
	quicBbr2DefaultLossThreshold = 0.02
	maxBbrBurstPackets           = 3
)

type bbrMode int

const (
	// Startup phase of the connection.
	bbrModeStartup = iota
	// After achieving the highest possible bandwidth during the startup, lower
	// the pacing rate in order to drain the queue.
	bbrModeDrain
	// Cruising mode.
	bbrModeProbeBw
	// Temporarily slow down sending in order to empty the buffer and measure
	// the real minimum RTT.
	bbrModeProbeRtt
)

// Indicates how the congestion control limits the amount of bytes in flight.
type bbrRecoveryState int

const (
	// Do not limit.
	bbrRecoveryStateNotInRecovery = iota
	// Allow an extra outstanding byte for each byte acknowledged.
	bbrRecoveryStateConservation
	// Allow two extra outstanding bytes for each byte acknowledged (slow
	// start).
	bbrRecoveryStateGrowth
)

type bbrSender struct {
	rttStats *utils.RTTStats
	clock    Clock
	rand     utils.Rand
	pacer    *pacer

	mode bbrMode

	// Bandwidth sampler provides BBR with the bandwidth measurements at
	// individual points.
	sampler *bandwidthSampler

	// The number of the round trips that have occurred during the connection.
	roundTripCount roundTripCount

	// The packet number of the most recently sent packet.
	lastSentPacket protocol.PacketNumber
	// Acknowledgement of any packet after |current_round_trip_end_| will cause
	// the round trip counter to advance.
	currentRoundTripEnd protocol.PacketNumber

	// Number of congestion events with some losses, in the current round.
	numLossEventsInRound uint64

	// Number of total bytes lost in the current round.
	bytesLostInRound protocol.ByteCount

	// The filter that tracks the maximum bandwidth over the multiple recent
	// round-trips.
	maxBandwidth *utils.WindowedFilter[Bandwidth, roundTripCount]

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

	// The smallest value the |congestion_window_| can achieve.
	minCongestionWindow protocol.ByteCount

	// The pacing gain applied during the STARTUP phase.
	highGain float64

	// The CWND gain applied during the STARTUP phase.
	highCwndGain float64

	// The pacing gain applied during the DRAIN phase.
	drainGain float64

	// The current pacing rate of the connection.
	pacingRate Bandwidth

	// The gain currently applied to the pacing rate.
	pacingGain float64
	// The gain currently applied to the congestion window.
	congestionWindowGain float64

	// The gain used for the congestion window during PROBE_BW.  Latched from
	// quic_bbr_cwnd_gain flag.
	congestionWindowGainConstant float64
	// The number of RTTs to stay in STARTUP mode.  Defaults to 3.
	numStartupRtts int64

	// Number of round-trips in PROBE_BW mode, used for determining the current
	// pacing gain cycle.
	cycleCurrentOffset int
	// The time at which the last pacing gain cycle was started.
	lastCycleStart time.Time

	// Indicates whether the connection has reached the full bandwidth mode.
	isAtFullBandwidth bool
	// Number of rounds during which there was no significant bandwidth increase.
	roundsWithoutBandwidthGain int64
	// The bandwidth compared to which the increase is measured.
	bandwidthAtLastRound Bandwidth

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
	// Indicates whether any non app-limited samples have been recorded.
	hasNoAppLimitedSample bool

	// Current state of recovery.
	recoveryState bbrRecoveryState
	// Receiving acknowledgement of a packet after |end_recovery_at_| will cause
	// BBR to exit the recovery mode.  A value above zero indicates at least one
	// loss has been detected, so it must not be set back to zero.
	endRecoveryAt protocol.PacketNumber
	// A window used to limit the number of bytes in flight during loss recovery.
	recoveryWindow protocol.ByteCount
	// If true, consider all samples in recovery app-limited.
	isAppLimitedRecovery bool // not used

	// When true, pace at 1.5x and disable packet conservation in STARTUP.
	slowerStartup bool // not used
	// When true, disables packet conservation in STARTUP.
	rateBasedStartup bool // not used

	// When true, add the most recent ack aggregation measurement during STARTUP.
	enableAckAggregationDuringStartup bool
	// When true, expire the windowed ack aggregation values in STARTUP when
	// bandwidth increases more than 25%.
	expireAckAggregationInStartup bool

	// If true, will not exit low gain mode until bytes_in_flight drops below BDP
	// or it's time for high gain mode.
	drainToTarget bool

	// If true, slow down pacing rate in STARTUP when overshooting is detected.
	detectOvershooting bool
	// Bytes lost while detect_overshooting_ is true.
	bytesLostWhileDetectingOvershooting protocol.ByteCount
	// Slow down pacing rate if
	// bytes_lost_while_detecting_overshooting_ *
	// bytes_lost_multiplier_while_detecting_overshooting_ > IW.
	bytesLostMultiplierWhileDetectingOvershooting uint8
	// When overshooting is detected, do not drop pacing_rate_ below this value /
	// min_rtt.
	cwndToCalculateMinPacingRate protocol.ByteCount

	// Max congestion window when adjusting network parameters.
	maxCongestionWindowWithNetworkParametersAdjusted protocol.ByteCount // not used

	// Params.
	maxDatagramSize protocol.ByteCount
	lastState       logging.CongestionState
	tracer          logging.ConnectionTracer
	// Recorded on packet sent. equivalent |unacked_packets_->bytes_in_flight()|
	bytesInFlight protocol.ByteCount
}

var (
	_ SendAlgorithm               = &bbrSender{}
	_ SendAlgorithmWithDebugInfos = &bbrSender{}
)

// NewCubicSender makes a new cubic sender
func NewBbrSender(
	clock Clock,
	rttStats *utils.RTTStats,
	initialMaxDatagramSize protocol.ByteCount,
	tracer logging.ConnectionTracer,
) *bbrSender {
	return newBbrSender(
		clock,
		rttStats,
		initialMaxDatagramSize,
		initialCongestionWindow*initialMaxDatagramSize,
		protocol.MaxCongestionWindowPackets*initialMaxDatagramSize,
		tracer,
	)
}

func newBbrSender(
	clock Clock,
	rttStats *utils.RTTStats,
	initialMaxDatagramSize,
	initialCongestionWindow,
	initialMaxCongestionWindow protocol.ByteCount,
	tracer logging.ConnectionTracer,
) *bbrSender {
	b := &bbrSender{
		clock:                        clock,
		rttStats:                     rttStats,
		mode:                         bbrModeStartup,
		sampler:                      newBandwidthSampler(roundTripCount(bandwidthWindowSize)),
		lastSentPacket:               protocol.InvalidPacketNumber,
		currentRoundTripEnd:          protocol.InvalidPacketNumber,
		maxBandwidth:                 utils.NewWindowedFilter(roundTripCount(bandwidthWindowSize), utils.MaxFilter[Bandwidth]),
		congestionWindow:             initialCongestionWindow,
		initialCongestionWindow:      initialCongestionWindow,
		maxCongestionWindow:          initialMaxCongestionWindow,
		minCongestionWindow:          defaultMinimumCongestionWindow,
		highGain:                     defaultHighGain,
		highCwndGain:                 defaultHighGain,
		drainGain:                    1.0 / defaultHighGain,
		pacingGain:                   1.0,
		congestionWindowGain:         1.0,
		congestionWindowGainConstant: 2.0,
		numStartupRtts:               roundTripsWithoutGrowthBeforeExitingStartup,
		recoveryState:                bbrRecoveryStateNotInRecovery,
		endRecoveryAt:                protocol.InvalidPacketNumber,
		recoveryWindow:               initialMaxCongestionWindow,
		bytesLostMultiplierWhileDetectingOvershooting:    2,
		cwndToCalculateMinPacingRate:                     initialCongestionWindow,
		maxCongestionWindowWithNetworkParametersAdjusted: initialMaxCongestionWindow,
		maxDatagramSize: initialMaxDatagramSize,
		tracer:          tracer,
	}
	b.pacer = newPacer(func() Bandwidth {
		return Bandwidth(float64(b.bandwidthEstimate()) * b.congestionWindowGain)
	})

	if b.tracer != nil {
		b.lastState = logging.CongestionStateStartup
		b.tracer.UpdatedCongestionState(logging.CongestionStateStartup)
	}

	b.enterStartupMode(b.clock.Now())
	b.setHighCwndGain(derivedHighCWNDGain)

	return b
}

// TimeUntilSend implements the SendAlgorithm interface.
func (b *bbrSender) TimeUntilSend(bytesInFlight protocol.ByteCount) time.Time {
	return b.pacer.TimeUntilSend()
}

// HasPacingBudget implements the SendAlgorithm interface.
func (b *bbrSender) HasPacingBudget(now time.Time) bool {
	return b.pacer.Budget(now) >= b.maxDatagramSize
}

// OnPacketSent implements the SendAlgorithm interface.
func (b *bbrSender) OnPacketSent(
	sentTime time.Time,
	bytesInFlight protocol.ByteCount,
	packetNumber protocol.PacketNumber,
	bytes protocol.ByteCount,
	isRetransmittable bool) {

	b.pacer.SentPacket(sentTime, bytes)

	b.lastSentPacket = packetNumber
	b.bytesInFlight = bytesInFlight

	if bytesInFlight == 0 {
		b.exitingQuiescence = true
	}

	b.sampler.OnPacketSent(sentTime, packetNumber, bytes, bytesInFlight, isRetransmittable)
}

// CanSend implements the SendAlgorithm interface.
func (b *bbrSender) CanSend(bytesInFlight protocol.ByteCount) bool {
	return bytesInFlight < b.GetCongestionWindow()
}

// MaybeExitSlowStart implements the SendAlgorithm interface.
func (b *bbrSender) MaybeExitSlowStart() {
	// Do nothing
}

// OnPacketAcked implements the SendAlgorithm interface.
func (b *bbrSender) OnPacketAcked(number protocol.PacketNumber, ackedBytes protocol.ByteCount, priorInFlight protocol.ByteCount, eventTime time.Time) {
	// Do nothing.
}

// OnPacketLost implements the SendAlgorithm interface.
func (b *bbrSender) OnPacketLost(number protocol.PacketNumber, lostBytes protocol.ByteCount, priorInFlight protocol.ByteCount) {
	// Do nothing.

}

// OnRetransmissionTimeout implements the SendAlgorithm interface.
func (b *bbrSender) OnRetransmissionTimeout(packetsRetransmitted bool) {
	// Do nothing.
}

// SetMaxDatagramSize implements the SendAlgorithm interface.
func (b *bbrSender) SetMaxDatagramSize(s protocol.ByteCount) {
	if s < b.maxDatagramSize {
		panic(fmt.Sprintf("congestion BUG: decreased max datagram size from %d to %d", b.maxDatagramSize, s))
	}
	cwndIsMinCwnd := b.congestionWindow == b.minCongestionWindow
	b.maxDatagramSize = s
	if cwndIsMinCwnd {
		b.congestionWindow = b.minCongestionWindow
	}
	b.pacer.SetMaxDatagramSize(s)
}

// InSlowStart implements the SendAlgorithmWithDebugInfos interface.
func (b *bbrSender) InSlowStart() bool {
	return b.mode == bbrModeStartup
}

// InRecovery implements the SendAlgorithmWithDebugInfos interface.
func (b *bbrSender) InRecovery() bool {
	return b.recoveryState != bbrRecoveryStateNotInRecovery
}

// GetCongestionWindow implements the SendAlgorithmWithDebugInfos interface.
func (b *bbrSender) GetCongestionWindow() protocol.ByteCount {
	if b.mode == bbrModeProbeRtt {
		return b.probeRttCongestionWindow()
	}

	if b.InRecovery() {
		return utils.Min(b.congestionWindow, b.recoveryWindow)
	}

	return b.congestionWindow
}

// OnCongestionEvent implemnets the CongestionEvent interface
func (b *bbrSender) OnCongestionEvent(priorInFlight protocol.ByteCount, eventTime time.Time, ackedPackets []protocol.AckedPacketInfo, lostPackets []protocol.LostPacketInfo) {
	totalBytesAckedBefore := b.sampler.TotalBytesAcked()
	totalBytesLostBefore := b.sampler.TotalBytesLost()

	var isRoundStart, minRttExpired bool
	var excessAcked, bytesLost protocol.ByteCount

	// The send state of the largest packet in acked_packets, unless it is
	// empty. If acked_packets is empty, it's the send state of the largest
	// packet in lost_packets.
	var lastPacketSendState sendTimeState

	b.maybeApplimited(priorInFlight)

	// Update bytesInFlight
	b.bytesInFlight = priorInFlight
	for _, p := range ackedPackets {
		b.bytesInFlight -= p.BytesAcked
	}
	for _, p := range lostPackets {
		b.bytesInFlight -= p.BytesLost
	}

	if len(ackedPackets) != 0 {
		lastAckedPacket := ackedPackets[len(ackedPackets)-1].PacketNumber
		isRoundStart = b.updateRoundTripCounter(lastAckedPacket)
		b.updateRecoveryState(lastAckedPacket, len(lostPackets) != 0, isRoundStart)
	}

	sample := b.sampler.OnCongestionEvent(eventTime,
		ackedPackets, lostPackets, b.maxBandwidth.GetBest(), infBandwidth, b.roundTripCount)
	if sample.lastPacketSendState.isValid {
		b.lastSampleIsAppLimited = sample.lastPacketSendState.isAppLimited
		b.hasNoAppLimitedSample = b.hasNoAppLimitedSample || !b.lastSampleIsAppLimited
	}
	// Avoid updating |max_bandwidth_| if a) this is a loss-only event, or b) all
	// packets in |acked_packets| did not generate valid samples. (e.g. ack of
	// ack-only packets). In both cases, sampler_.total_bytes_acked() will not
	// change.
	if totalBytesAckedBefore != b.sampler.TotalBytesAcked() {
		if !sample.sampleIsAppLimited || sample.sampleMaxBandwidth > b.maxBandwidth.GetBest() {
			b.maxBandwidth.Update(sample.sampleMaxBandwidth, b.roundTripCount)
		}
	}

	if sample.sampleRtt != infRTT {
		minRttExpired = b.maybeUpdateMinRtt(eventTime, sample.sampleRtt)
	}
	bytesLost = b.sampler.TotalBytesLost() - totalBytesLostBefore

	excessAcked = sample.extraAcked
	lastPacketSendState = sample.lastPacketSendState

	if len(lostPackets) != 0 {
		b.numLossEventsInRound++
		b.bytesLostInRound += bytesLost
	}

	// Handle logic specific to PROBE_BW mode.
	if b.mode == bbrModeProbeBw {
		b.updateGainCyclePhase(eventTime, priorInFlight, len(lostPackets) != 0)
	}

	// Handle logic specific to STARTUP and DRAIN modes.
	if isRoundStart && !b.isAtFullBandwidth {
		b.checkIfFullBandwidthReached(&lastPacketSendState)
	}

	b.maybeExitStartupOrDrain(eventTime)

	// Handle logic specific to PROBE_RTT.
	b.maybeEnterOrExitProbeRtt(eventTime, isRoundStart, minRttExpired)

	// Calculate number of packets acked and lost.
	bytesAcked := b.sampler.TotalBytesAcked() - totalBytesAckedBefore

	// After the model is updated, recalculate the pacing rate and congestion
	// window.
	b.calculatePacingRate(bytesLost)
	b.calculateCongestionWindow(bytesAcked, excessAcked)
	b.calculateRecoveryWindow(bytesAcked, bytesLost)

	// Cleanup internal state.
	if len(lostPackets) != 0 {
		lastLostPacket := lostPackets[len(lostPackets)-1].PacketNumber
		b.sampler.RemoveObsoletePackets(lastLostPacket)
	}
	if isRoundStart {
		b.numLossEventsInRound = 0
		b.bytesLostInRound = 0
	}

}

func (b *bbrSender) PacingRate() Bandwidth {
	if b.pacingRate == 0 {
		return Bandwidth(b.highGain * float64(
			BandwidthFromDelta(b.initialCongestionWindow, b.getMinRtt())))
	}

	return b.pacingRate
}

func (b *bbrSender) hasGoodBandwidthEstimateForResumption() bool {
	return b.hasNonAppLimitedSample()
}

func (b *bbrSender) hasNonAppLimitedSample() bool {
	return b.hasNoAppLimitedSample
}

// Sets the pacing gain used in STARTUP.  Must be greater than 1.
func (b *bbrSender) setHighGain(highGain float64) {
	b.highGain = highGain
	if b.mode == bbrModeStartup {
		b.pacingGain = highGain
	}
}

// Sets the CWND gain used in STARTUP.  Must be greater than 1.
func (b *bbrSender) setHighCwndGain(highCwndGain float64) {

	b.highCwndGain = highCwndGain
	if b.mode == bbrModeStartup {
		b.congestionWindowGain = highCwndGain
	}
}

// Sets the gain used in DRAIN.  Must be less than 1.
func (b *bbrSender) setDrainGain(drainGain float64) {
	b.drainGain = drainGain
}

// What's the current estimated bandwidth in bytes per second.
func (b *bbrSender) bandwidthEstimate() Bandwidth {
	return b.maxBandwidth.GetBest()
}

// Returns the current estimate of the RTT of the connection.  Outside of the
// edge cases, this is minimum RTT.
func (b *bbrSender) getMinRtt() time.Duration {
	if b.minRtt != 0 {
		return b.minRtt
	}
	// min_rtt could be available if the handshake packet gets neutered then
	// gets acknowledged. This could only happen for QUIC crypto where we do not
	// drop keys.
	return b.rttStats.MinOrInitialRtt()
}

// Computes the target congestion window using the specified gain.
func (b *bbrSender) getTargetCongestionWindow(gain float64) protocol.ByteCount {
	bdp := bdpFromRttAndBandwidth(b.getMinRtt(), b.bandwidthEstimate())
	congestionWindow := protocol.ByteCount(gain * float64(bdp))

	// BDP estimate will be zero if no bandwidth samples are available yet.
	if congestionWindow == 0 {
		congestionWindow = protocol.ByteCount(gain * float64(b.initialCongestionWindow))
	}

	return utils.Max(congestionWindow, b.minCongestionWindow)
}

// The target congestion window during PROBE_RTT.
func (b *bbrSender) probeRttCongestionWindow() protocol.ByteCount {
	return b.minCongestionWindow
}

func (b *bbrSender) maybeUpdateMinRtt(now time.Time, sampleMinRtt time.Duration) bool {
	// Do not expire min_rtt if none was ever available.
	minRttExpired := b.minRtt != 0 && now.After(b.minRttTimestamp.Add(minRttExpiry))
	if minRttExpired || sampleMinRtt < b.minRtt || b.minRtt == 0 {
		b.minRtt = sampleMinRtt
		b.minRttTimestamp = now
	}

	return minRttExpired
}

// Enters the STARTUP mode.
func (b *bbrSender) enterStartupMode(now time.Time) {
	b.mode = bbrModeStartup
	b.maybeTraceStateChange(logging.CongestionStateStartup)
	b.pacingGain = b.highGain
	b.congestionWindowGain = b.highCwndGain
}

// Enters the PROBE_BW mode.
func (b *bbrSender) enterProbeBandwidthMode(now time.Time) {
	b.mode = bbrModeProbeBw
	b.maybeTraceStateChange(logging.CongestionStateProbeBw)
	b.congestionWindowGain = b.congestionWindowGainConstant

	// Pick a random offset for the gain cycle out of {0, 2..7} range. 1 is
	// excluded because in that case increased gain and decreased gain would not
	// follow each other.
	b.cycleCurrentOffset = int(b.rand.Int31n(protocol.PacketsPerConnectionID)) % (gainCycleLength - 1)
	if b.cycleCurrentOffset >= 1 {
		b.cycleCurrentOffset += 1
	}

	b.lastCycleStart = now
	b.pacingGain = pacingGain[b.cycleCurrentOffset]
}

// Updates the round-trip counter if a round-trip has passed.  Returns true if
// the counter has been advanced.
func (b *bbrSender) updateRoundTripCounter(lastAckedPacket protocol.PacketNumber) bool {
	if b.currentRoundTripEnd == protocol.InvalidPacketNumber || lastAckedPacket > b.currentRoundTripEnd {
		b.roundTripCount++
		b.currentRoundTripEnd = b.lastSentPacket
		return true
	}
	return false
}

// Updates the current gain used in PROBE_BW mode.
func (b *bbrSender) updateGainCyclePhase(now time.Time, priorInFlight protocol.ByteCount, hasLosses bool) {
	// In most cases, the cycle is advanced after an RTT passes.
	shouldAdvanceGainCycling := now.After(b.lastCycleStart.Add(b.getMinRtt()))
	// If the pacing gain is above 1.0, the connection is trying to probe the
	// bandwidth by increasing the number of bytes in flight to at least
	// pacing_gain * BDP.  Make sure that it actually reaches the target, as long
	// as there are no losses suggesting that the buffers are not able to hold
	// that much.
	if b.pacingGain > 1.0 && !hasLosses && priorInFlight < b.getTargetCongestionWindow(b.pacingGain) {
		shouldAdvanceGainCycling = false
	}

	// If pacing gain is below 1.0, the connection is trying to drain the extra
	// queue which could have been incurred by probing prior to it.  If the number
	// of bytes in flight falls down to the estimated BDP value earlier, conclude
	// that the queue has been successfully drained and exit this cycle early.
	if b.pacingGain < 1.0 && b.bytesInFlight <= b.getTargetCongestionWindow(1) {
		shouldAdvanceGainCycling = true
	}

	if shouldAdvanceGainCycling {
		b.cycleCurrentOffset = (b.cycleCurrentOffset + 1) % gainCycleLength
		b.lastCycleStart = now
		// Stay in low gain mode until the target BDP is hit.
		// Low gain mode will be exited immediately when the target BDP is achieved.
		if b.drainToTarget && b.pacingGain < 1 &&
			pacingGain[b.cycleCurrentOffset] == 1 &&
			b.bytesInFlight > b.getTargetCongestionWindow(1) {
			return
		}
		b.pacingGain = pacingGain[b.cycleCurrentOffset]
	}
}

// Tracks for how many round-trips the bandwidth has not increased
// significantly.
func (b *bbrSender) checkIfFullBandwidthReached(lastPacketSendState *sendTimeState) {
	if b.lastSampleIsAppLimited {
		return
	}

	target := Bandwidth(float64(b.bandwidthAtLastRound) * startupGrowthTarget)
	if b.bandwidthEstimate() >= target {
		b.bandwidthAtLastRound = b.bandwidthEstimate()
		b.roundsWithoutBandwidthGain = 0
		if b.expireAckAggregationInStartup {
			// Expire old excess delivery measurements now that bandwidth increased.
			b.sampler.ResetMaxAckHeightTracker(0, b.roundTripCount)
		}
		return
	}

	b.roundsWithoutBandwidthGain++
	if b.roundsWithoutBandwidthGain >= b.numStartupRtts ||
		b.shouldExitStartupDueToLoss(lastPacketSendState) {
		b.isAtFullBandwidth = true
	}
}

func (b *bbrSender) maybeApplimited(bytesInFlight protocol.ByteCount) {
	congestionWindow := b.GetCongestionWindow()
	if bytesInFlight >= congestionWindow {
		return
	}
	availableBytes := congestionWindow - bytesInFlight
	drainLimited := b.mode == bbrModeDrain && bytesInFlight > congestionWindow/2
	if !drainLimited || availableBytes > maxBbrBurstPackets*b.maxDatagramSize {
		b.sampler.OnAppLimited()
	}
}

// Transitions from STARTUP to DRAIN and from DRAIN to PROBE_BW if
// appropriate.
func (b *bbrSender) maybeExitStartupOrDrain(now time.Time) {
	if b.mode == bbrModeStartup && b.isAtFullBandwidth {
		b.mode = bbrModeDrain
		b.maybeTraceStateChange(logging.CongestionStateDrain)
		b.pacingGain = b.drainGain
		b.congestionWindowGain = b.highCwndGain
	}
	if b.mode == bbrModeDrain && b.bytesInFlight <= b.getTargetCongestionWindow(1) {
		b.enterProbeBandwidthMode(now)
	}
}

// Decides whether to enter or exit PROBE_RTT.
func (b *bbrSender) maybeEnterOrExitProbeRtt(now time.Time, isRoundStart, minRttExpired bool) {
	if minRttExpired && !b.exitingQuiescence && b.mode != bbrModeProbeRtt {
		b.mode = bbrModeProbeRtt
		b.maybeTraceStateChange(logging.CongestionStateProbRtt)
		b.pacingGain = 1.0
		// Do not decide on the time to exit PROBE_RTT until the |bytes_in_flight|
		// is at the target small value.
		b.exitProbeRttAt = time.Time{}
	}

	if b.mode == bbrModeProbeRtt {
		b.sampler.OnAppLimited()
		b.maybeTraceStateChange(logging.CongestionStateApplicationLimited)

		if b.exitProbeRttAt.IsZero() {
			// If the window has reached the appropriate size, schedule exiting
			// PROBE_RTT.  The CWND during PROBE_RTT is kMinimumCongestionWindow, but
			// we allow an extra packet since QUIC checks CWND before sending a
			// packet.
			if b.bytesInFlight < b.probeRttCongestionWindow()+protocol.MaxPacketBufferSize {
				b.exitProbeRttAt = now.Add(probeRttTime)
				b.probeRttRoundPassed = false
			}
		} else {
			if isRoundStart {
				b.probeRttRoundPassed = true
			}
			if now.Sub(b.exitProbeRttAt) >= 0 && b.probeRttRoundPassed {
				b.minRttTimestamp = now
				if !b.isAtFullBandwidth {
					b.enterStartupMode(now)
				} else {
					b.enterProbeBandwidthMode(now)
				}
			}
		}
	}

	b.exitingQuiescence = false
}

// Determines whether BBR needs to enter, exit or advance state of the
// recovery.
func (b *bbrSender) updateRecoveryState(lastAckedPacket protocol.PacketNumber, hasLosses, isRoundStart bool) {
	// Disable recovery in startup, if loss-based exit is enabled.
	if !b.isAtFullBandwidth {
		return
	}

	// Exit recovery when there are no losses for a round.
	if hasLosses {
		b.endRecoveryAt = b.lastSentPacket
	}

	switch b.recoveryState {
	case bbrRecoveryStateNotInRecovery:
		if hasLosses {
			b.recoveryState = bbrRecoveryStateConservation
			// This will cause the |recovery_window_| to be set to the correct
			// value in CalculateRecoveryWindow().
			b.recoveryWindow = 0
			// Since the conservation phase is meant to be lasting for a whole
			// round, extend the current round as if it were started right now.
			b.currentRoundTripEnd = b.lastSentPacket
		}
	case bbrRecoveryStateConservation:
		if isRoundStart {
			b.recoveryState = bbrRecoveryStateGrowth
		}
		fallthrough
	case bbrRecoveryStateGrowth:
		// Exit recovery if appropriate.
		if !hasLosses && lastAckedPacket > b.endRecoveryAt {
			b.recoveryState = bbrRecoveryStateNotInRecovery
		}
	}
}

// Determines the appropriate pacing rate for the connection.
func (b *bbrSender) calculatePacingRate(bytesLost protocol.ByteCount) {
	if b.bandwidthEstimate() == 0 {
		return
	}

	targetRate := Bandwidth(b.pacingGain * float64(b.bandwidthEstimate()))
	if b.isAtFullBandwidth {
		b.pacingRate = targetRate
		return
	}

	// Pace at the rate of initial_window / RTT as soon as RTT measurements are
	// available.
	if b.pacingRate == 0 && b.rttStats.MinRTT() != 0 {
		b.pacingRate = BandwidthFromDelta(b.initialCongestionWindow, b.rttStats.MinRTT())
		return
	}

	if b.detectOvershooting {
		b.bytesLostWhileDetectingOvershooting += bytesLost
		// Check for overshooting with network parameters adjusted when pacing rate
		// > target_rate and loss has been detected.
		if b.pacingRate > targetRate && b.bytesLostWhileDetectingOvershooting > 0 {
			if b.hasNoAppLimitedSample ||
				b.bytesLostWhileDetectingOvershooting*protocol.ByteCount(b.bytesLostMultiplierWhileDetectingOvershooting) > b.initialCongestionWindow {
				// We are fairly sure overshoot happens if 1) there is at least one
				// non app-limited bw sample or 2) half of IW gets lost. Slow pacing
				// rate.
				b.pacingRate = utils.Max(targetRate, BandwidthFromDelta(b.cwndToCalculateMinPacingRate, b.rttStats.MinRTT()))
				b.bytesLostWhileDetectingOvershooting = 0
				b.detectOvershooting = false
			}
		}
	}

	// Do not decrease the pacing rate during startup.
	b.pacingRate = utils.Max(b.pacingRate, targetRate)
}

// Determines the appropriate congestion window for the connection.
func (b *bbrSender) calculateCongestionWindow(bytesAcked, excessAcked protocol.ByteCount) {
	if b.mode == bbrModeProbeRtt {
		return
	}

	targetWindow := b.getTargetCongestionWindow(b.congestionWindowGain)
	if b.isAtFullBandwidth {
		// Add the max recently measured ack aggregation to CWND.
		targetWindow += b.sampler.MaxAckHeight()
	} else if b.enableAckAggregationDuringStartup {
		// Add the most recent excess acked.  Because CWND never decreases in
		// STARTUP, this will automatically create a very localized max filter.
		targetWindow += excessAcked
	}

	// Instead of immediately setting the target CWND as the new one, BBR grows
	// the CWND towards |target_window| by only increasing it |bytes_acked| at a
	// time.
	if b.isAtFullBandwidth {
		b.congestionWindow = utils.Min(targetWindow, b.congestionWindow+bytesAcked)
	} else if b.congestionWindow < targetWindow ||
		b.sampler.TotalBytesAcked() < b.initialCongestionWindow {
		// If the connection is not yet out of startup phase, do not decrease the
		// window.
		b.congestionWindow += bytesAcked
	}

	// Enforce the limits on the congestion window.
	b.congestionWindow = utils.Max(b.congestionWindow, b.minCongestionWindow)
	b.congestionWindow = utils.Min(b.congestionWindow, b.maxCongestionWindow)
}

// Determines the appropriate window that constrains the in-flight during recovery.
func (b *bbrSender) calculateRecoveryWindow(bytesAcked, bytesLost protocol.ByteCount) {
	if b.recoveryState == bbrRecoveryStateNotInRecovery {
		return
	}

	// Set up the initial recovery window.
	if b.recoveryWindow == 0 {
		b.recoveryWindow = b.bytesInFlight + bytesAcked
		b.recoveryWindow = utils.Max(b.minCongestionWindow, b.recoveryWindow)
		return
	}

	// Remove losses from the recovery window, while accounting for a potential
	// integer underflow.
	if b.recoveryWindow >= bytesLost {
		b.recoveryWindow = b.recoveryWindow - bytesLost
	} else {
		b.recoveryWindow = b.maxDatagramSize
	}

	// In CONSERVATION mode, just subtracting losses is sufficient.  In GROWTH,
	// release additional |bytes_acked| to achieve a slow-start-like behavior.
	if b.recoveryState == bbrRecoveryStateGrowth {
		b.recoveryWindow += bytesAcked
	}

	// Always allow sending at least |bytes_acked| in response.
	b.recoveryWindow = utils.Max(b.recoveryWindow, b.bytesInFlight+bytesAcked)
	b.recoveryWindow = utils.Max(b.minCongestionWindow, b.recoveryWindow)
}

// Return whether we should exit STARTUP due to excessive loss.
func (b *bbrSender) shouldExitStartupDueToLoss(lastPacketSendState *sendTimeState) bool {
	if b.numLossEventsInRound < defaultStartupFullLossCount || !lastPacketSendState.isValid {
		return false
	}

	inflightAtSend := lastPacketSendState.bytesInFlight

	if inflightAtSend > 0 && b.bytesLostInRound > 0 {
		if b.bytesLostInRound > protocol.ByteCount(float64(inflightAtSend)*quicBbr2DefaultLossThreshold) {
			return true
		}
		return false
	}
	return false
}

func bdpFromRttAndBandwidth(rtt time.Duration, bandwidth Bandwidth) protocol.ByteCount {
	return protocol.ByteCount(rtt) * protocol.ByteCount(bandwidth) / protocol.ByteCount(BytesPerSecond) / protocol.ByteCount(time.Second)
}

func (b *bbrSender) maybeTraceStateChange(new logging.CongestionState) {
	if b.tracer == nil || new == b.lastState {
		return
	}
	b.tracer.UpdatedCongestionState(new)
	b.lastState = new
}
