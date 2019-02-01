package congestion

import (
	"math/rand"
	"time"

	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/utils"
)

type RoundTripCount uint64

type Mode uint
type RecoveryState uint

// Constants based on TCP defaults.
// The minimum CWND to ensure delayed acks don't reduce bandwidth measurements.
// Does not inflate the pacing rate.
const _defaultMinimumCongestionWindow = 4 * protocol.MaxSegmentSize

// The gain used for the STARTUP, equal to 2/ln(2).
const defaultHighGain float32 = 2.885

// The newly derived gain for STARTUP, equal to 4 * ln(2)
const derivedHighGain float32 = 2.773

// The newly derived CWND gain for STARTUP, 2.
const derivedHighCWNDGain float32 = 2.773

// The gain used in STARTUP after loss has been detected.
// 1.5 is enough to allow for 25% exogenous loss and still observe a 25% growth
// in measured bandwidth.
const startupAfterLossGain float32 = 1.5

// The cycle of gains used during the PROBE_BW stage.
var pacingGain = [8]float32{1.25, 0.75, 1, 1, 1, 1, 1, 1}

// The length of the gain cycle.
const gainCycleLength = len(pacingGain)

// The size of the bandwidth filter window, in round-trips.
const bandwidthWindowSize RoundTripCount = RoundTripCount(gainCycleLength + 2)

// The time after which the current minRtt value expires.
const minRttExpiry time.Duration = time.Duration(10) * time.Second

// The minimum time the connection can spend in PROBE_RTT mode.
const probeRttTime time.Duration = time.Duration(200) * time.Millisecond

// If the bandwidth does not increase by the factor of |startupGrowthTarget|
// within |roundTripsWithoutGrowthBeforeExitingStartup| rounds, the connection
// will exit the STARTUP mode.
const startupGrowthTarget float32 = 1.25
const roundTripsWithoutGrowthBeforeExitingStartup RoundTripCount = 3

// Coefficient of target congestion window to use when basing PROBE_RTT on BDP.
const moderateProbeRttMultiplier float32 = 0.75

// Coefficient to determine if a new RTT is sufficiently similar to minRtt that
// we don't need to enter PROBE_RTT.
const similarMinRttThreshold float32 = 1.125

const (
	// Startup phase of the connection.
	STARTUP Mode = iota
	// After achieving the highest possible bandwidth during the startup, lower
	// the pacing rate in order to drain the queue.
	DRAIN
	// Cruising mode.
	PROBE_BW
	// Temporarily slow down sending in order to empty the buffer and measure
	// the real minimum RTT.
	PROBE_RTT
)

// Indicates how the congestion control limits the amount of bytes in flight.
const (
	// Do not limit.
	NOT_IN_RECOVERY RecoveryState = iota
	// Allow an extra outstanding byte for each byte acknowledged.
	CONSERVATION
	// Allow two extra outstanding bytes for each byte acknowledged (slow
	// start).
	GROWTH
)

type BbrSender struct {

	// Debug state can be exported in order to troubleshoot potential congestion
	// control issues.
	DebugState struct {
		mode             Mode
		maxBandwidth     Bandwidth
		roundTripCount   RoundTripCount
		gainCycleIndex   int
		congestionWindow protocol.ByteCount

		isAtFullBandwidth          bool
		bandwidthAtLastRound       Bandwidth
		roundsWithoutBandwidthGain RoundTripCount

		minRtt          time.Duration
		minRttTimestamp time.Time

		recoveryState  RecoveryState
		recoveryWindow protocol.ByteCount

		lastSampleIsAppLimited bool
		endOfAppLimitedPhase   protocol.PacketNumber
	}

	rttStats       *RTTStats
	unackedPackets *UnackedPacketMap
	random_        *rand.Rand
	mode_          Mode

	// Bandwidth sampler provides BBR with the bandwidth measurements at
	// individual points.
	sampler_ BandwidthSampler

	// The number of the round trips that have occurred during the connection.
	roundTripCount RoundTripCount

	// The packet number of the most recently sent packet.
	lastSentPacket protocol.PacketNumber
	// Acknowledgement of any packet after |currentRoundTripEnd| will cause
	// the round trip counter to advance.
	currentRoundTripEnd protocol.PacketNumber

	// The filter that tracks the maximum bandwidth over the multiple recent
	// round-trips.
	max_bandwidth_ MaxBandwidthFilter

	// Tracks the maximum number of bytes acked faster than the sending rate.
	max_ack_height_ MaxAckHeightFilter

	// The time this aggregation started and the number of bytes acked during it.
	aggregationEpochStartTime time.Time
	aggregationEpochBytes     protocol.ByteCount

	// Minimum RTT estimate.  Automatically expires within 10 seconds (and
	// triggers PROBE_RTT mode) if no new value is sampled during that period.
	minRtt time.Duration
	// The time at which the current value of |minRtt| was assigned.
	minRttTimestamp time.Time

	// The maximum allowed number of bytes in flight.
	congestionWindow protocol.ByteCount

	// The initial value of the |congestionWindow|.
	initialCongestionWindow protocol.ByteCount

	// The largest value the |congestionWindow| can achieve.
	maxCongestionWindow protocol.ByteCount

	// The smallest value the |congestionWindow| can achieve.
	minCongestionWindow protocol.ByteCount

	// The pacing gain applied during the STARTUP phase.
	highGain float32

	// The CWND gain applied during the STARTUP phase.
	highCwndGain float32

	// The pacing gain applied during the DRAIN phase.
	drainGain float32

	// The current pacing rate of the connection.
	pacingRate Bandwidth

	// The gain currently applied to the pacing rate.
	pacingGain float32
	// The gain currently applied to the congestion window.
	congestionWindowGain float32

	// The gain used for the congestion window during PROBE_BW.  Latched from
	// quic_bbr_cwnd_gain flag.
	congestionWindowGainConstant float32
	// The number of RTTs to stay in STARTUP mode.  Defaults to 3.
	numStartupRtts RoundTripCount
	// If true, exit startup if 1RTT has passed with no bandwidth increase and
	// the connection is in recovery.
	exitStartupOnLoss bool

	// Number of round-trips in PROBE_BW mode, used for determining the current
	// pacing gain cycle.
	cycleCurrentOffset int
	// The time at which the last pacing gain cycle was started.
	lastCycleStart time.Time

	// Indicates whether the connection has reached the full bandwidth mode.
	isAtFullBandwidth bool
	// Number of rounds during which there was no significant bandwidth increase.
	roundsWithoutBandwidthGain RoundTripCount
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
	hasNonAppLimitedSample bool
	// Indicates app-limited calls should be ignored as long as there's
	// enough data inflight to see more bandwidth when necessary.
	flexibleAppLimited bool

	// Current state of recovery.
	recoveryState RecoveryState
	// Receiving acknowledgement of a packet after |endRecoveryAt| will cause
	// BBR to exit the recovery mode.  A value above zero indicates at least one
	// loss has been detected, so it must not be set back to zero.
	endRecoveryAt protocol.PacketNumber
	// A window used to limit the number of bytes in flight during loss recovery.
	recoveryWindow protocol.ByteCount
	// If true, consider all samples in recovery app-limited.
	isAppLimitedRecovery bool

	// When true, pace at 1.5x and disable packet conservation in STARTUP.
	slowerStartup bool
	// When true, disables packet conservation in STARTUP.
	rateBasedStartup bool
	// When non-zero, decreases the rate in STARTUP by the total number of bytes
	// lost in STARTUP divided by CWND.
	startupRateReductionMultiplier uint8
	// Sum of bytes lost in STARTUP.
	startupBytesLost protocol.ByteCount

	// When true, add the most recent ack aggregation measurement during STARTUP.
	enableAckAggregationDuringStartup bool
	// When true, expire the windowed ack aggregation values in STARTUP when
	// bandwidth increases more than 25%.
	expireAckAggregationInStartup bool

	// If true, will not exit low gain mode until bytes_in_flight drops below BDP
	// or it's time for high gain mode.
	drainToTarget bool

	// If true, use a CWND of 0.75*BDP during probe_rtt instead of 4 packets.
	probeRttBasedOnBdp bool
	// If true, skip probe_rtt and update the timestamp of the existing minRtt to
	// now if minRtt over the last cycle is within 12.5% of the current minRtt.
	// Even if the minRtt is 12.5% too low, the 25% gain cycling and 2x CWND gain
	// should overcome an overly small minRtt.
	probeRttSkippedIfSimilarRtt bool
	// If true, disable PROBE_RTT entirely as long as the connection was recently
	// app limited.
	probeRttDisabledIfAppLimited bool
	appLimitedSinceLastProbeRtt  bool
	minRttSinceLastProbeRtt      time.Duration
}

func NewBbrSender(
	rttStats *RTTStats,
	unackedPackets *UnackedPacketMap,
	initialTcpCongestionWindow protocol.PacketCount,
	maxTcpCongestionWindow protocol.PacketCount,
	random *rand.Rand) *BbrSender {
	cwnd, mcwnd := protocol.ByteCount(initialTcpCongestionWindow) * protocol.DefaultTCPMSS,
									protocol.ByteCount(maxTcpCongestionWindow) * protocol.DefaultTCPMSS
	bbrSender := &BbrSender{
		rttStats:       rttStats,
		unackedPackets: unackedPackets,
		random_:        random,
		mode_:          STARTUP,
		roundTripCount: 0,
		max_bandwidth_ : *NewMaxBandwidthFilter(bandwidthWindowSize, 0, 0),
		max_ack_height_ : *NewMaxAckHeightFilter(bandwidthWindowSize, 0, 0),
		//aggregation_epoch_start_time_:QuicTime::Zero()
		aggregationEpochBytes:   0,
		minRtt:                  time.Duration(0),
		congestionWindow:        cwnd,
		initialCongestionWindow: cwnd,
		maxCongestionWindow:     mcwnd,
		minCongestionWindow:     _defaultMinimumCongestionWindow,
		highGain:                defaultHighGain,
		highCwndGain:            defaultHighGain,
		drainGain:               1.0 / defaultHighGain,
		pacingRate:0,
		pacingGain:                   1,
		congestionWindowGain:         1,
		congestionWindowGainConstant: utils.FLAGS_bbr_cwnd_gain,
		numStartupRtts:               roundTripsWithoutGrowthBeforeExitingStartup,
		exitStartupOnLoss:            false,
		cycleCurrentOffset:           0,
		//last_cycle_start_(QuicTime::Zero(),
		isAtFullBandwidth:          false,
		roundsWithoutBandwidthGain: 0,
		bandwidthAtLastRound:       0,
		exitingQuiescence:          false,
		//exit_probe_rtt_at_:QuicTime::Zero(),
		probeRttRoundPassed:               false,
		lastSampleIsAppLimited:            false,
		hasNonAppLimitedSample:            false,
		flexibleAppLimited:                false,
		recoveryState:                     NOT_IN_RECOVERY,
		recoveryWindow:                    mcwnd,
		isAppLimitedRecovery:              false,
		slowerStartup:                     false,
		rateBasedStartup:                  false,
		startupRateReductionMultiplier:    0,
		startupBytesLost:                  0,
		enableAckAggregationDuringStartup: false,
		expireAckAggregationInStartup:     false,
		drainToTarget:                     false,
		probeRttBasedOnBdp:                false,
		probeRttSkippedIfSimilarRtt:       false,
		probeRttDisabledIfAppLimited:      false,
		appLimitedSinceLastProbeRtt:       false,
		minRttSinceLastProbeRtt:           time.Duration(^uint(0)),
	}
	bbrSender.EnterStartupMode()
	return bbrSender
}

func (b *BbrSender) SetInitialCongestionWindowInPackets(congestionWindow protocol.PacketCount) {
	if b.mode_ == STARTUP {
		b.initialCongestionWindow = protocol.ByteCount(congestionWindow) * protocol.DefaultTCPMSS
		b.congestionWindow = protocol.ByteCount(congestionWindow) * protocol.DefaultTCPMSS
	}
}

func (b *BbrSender) InSlowStart() bool {
	return b.mode_ == STARTUP
}

func (b *BbrSender) OnPacketSent(
	sentTime time.Time,
	bytesInFlight protocol.ByteCount,
	packetNumber protocol.PacketNumber,
	bytes protocol.ByteCount,
	isRetransmittable bool) {
	b.lastSentPacket = packetNumber

	if bytesInFlight == 0 && b.sampler_.IsAppLimited() {
		b.exitingQuiescence = true
	}

	if !b.aggregationEpochStartTime.IsZero() {
		b.aggregationEpochStartTime = sentTime
	}

	b.sampler_.OnPacketSent(sentTime, packetNumber, bytes, bytesInFlight,
		isRetransmittable)
}

func (b *BbrSender) BandwidthEstimate() Bandwidth {
	return b.max_bandwidth_.GetBest();
}

func (b *BbrSender) GetCongestionWindow() protocol.ByteCount {
	if b.mode_ == PROBE_RTT {
		return b.ProbeRttCongestionWindow()
	}

	if b.InRecovery() && !(b.rateBasedStartup && b.mode_ == STARTUP) {
		return utils.MinByteCount(protocol.ByteCount(b.congestionWindow), protocol.ByteCount(b.recoveryWindow))
	}

	return b.congestionWindow
}

func (b *BbrSender) CanSend(bytes_in_flight protocol.ByteCount) bool {
	return bytes_in_flight < b.GetCongestionWindow()
}

func (b *BbrSender) PacingRate(bytes_in_flight protocol.ByteCount) Bandwidth {
	if b.pacingRate == 0 {
		return Bandwidth(b.highGain) * BandwidthFromDelta(
			b.initialCongestionWindow, b.GetMinRtt())
	}
	return b.pacingRate
}

//func (b *BbrSender) BandwidthEstimate() Bandwidth {
//		return b.max_bandwidth_.GetBest();
//}

func (b *BbrSender) SlowStartThreshold() protocol.ByteCount {
	return 0
}

func (b *BbrSender) InRecovery() bool {
	return b.recoveryState != NOT_IN_RECOVERY
}

func (b *BbrSender) ShouldSendProbingPacket() bool {
	if b.pacingGain <= 1 {
		return false
	}

	// TODO(b/77975811): If the pipe is highly under-utilized, consider not
	// sending a probing transmission, because the extra bandwidth is not needed.
	// If flexible_app_limited is enabled, check if the pipe is sufficiently full.
	if b.flexibleAppLimited {
		return !b.IsPipeSufficientlyFull()
	} else {
		return true
	}
}

func (b *BbrSender) IsPipeSufficientlyFull() bool {
	// See if we need more bytes in flight to see more bandwidth.
	if b.mode_ == STARTUP {
		// STARTUP exits if it doesn't observe a 25% bandwidth increase, so the CWND
		// must be more than 25% above the target.
		return b.unackedPackets.BytesInFlight() >=
			b.GetTargetCongestionWindow(1.5)
	}
	if b.pacingGain > 1 {
		// Super-unity PROBE_BW doesn't exit until 1.25 * BDP is achieved.
		return b.unackedPackets.BytesInFlight() >=
			b.GetTargetCongestionWindow(b.pacingGain)
	}
	// If bytes_in_flight are above the target congestion window, it should be
	// possible to observe the same or more bandwidth if it's available.
	return b.unackedPackets.BytesInFlight() >= b.GetTargetCongestionWindow(1.1)
}

func (b *BbrSender) OnCongestionEvent(
	priorInFlight protocol.ByteCount,
	eventTime time.Time,
	ackedPackets []AckedPacket,
	lostPackets []LostPacket) {
	totalBytesAckedBefore := b.sampler_.TotalBytesAcked()

	is_round_start := false
	min_rtt_expired := false

	b.DiscardLostPackets(lostPackets)

	// Input the new data into the BBR model of the connection.
	var excessAcked protocol.ByteCount = 0
	if len(ackedPackets) > 0 {
		lastAckedPacket := ackedPackets[len(ackedPackets)-1].packetNumber
		is_round_start = b.UpdateRoundTripCounter(lastAckedPacket)
		min_rtt_expired = b.UpdateBandwidthAndMinRtt(eventTime, ackedPackets)
		b.UpdateRecoveryState(lastAckedPacket, len(ackedPackets) > 0,
			is_round_start)

		bytes_acked := b.sampler_.TotalBytesAcked() - totalBytesAckedBefore

		excessAcked = b.UpdateAckAggregationBytes(eventTime, bytes_acked)
	}

	// Handle logic specific to PROBE_BW mode.
	if b.mode_ == PROBE_BW {
		b.UpdateGainCyclePhase(eventTime, priorInFlight, len(lostPackets)>0)
	}

	// Handle logic specific to STARTUP and DRAIN modes.
	if is_round_start && !b.isAtFullBandwidth {
		b.CheckIfFullBandwidthReached()
	}
	b.MaybeExitStartupOrDrain(eventTime)

	// Handle logic specific to PROBE_RTT.
	b.MaybeEnterOrExitProbeRtt(eventTime, is_round_start, min_rtt_expired)

	// Calculate number of packets acked and lost.
	bytesAcked := b.sampler_.totalBytesAcked - totalBytesAckedBefore
	var bytesLost protocol.ByteCount = 0
	for _, packet := range lostPackets {
		bytesLost += protocol.ByteCount(packet.bytesLost)
	}

	// After the model is updated, recalculate the pacing rate and congestion
	// window.
	b.CalculatePacingRate()
	b.CalculateCongestionWindow(bytesAcked, excessAcked)
	b.CalculateRecoveryWindow(bytesAcked, bytesLost)

	// Cleanup internal state.
	b.sampler_.RemoveObsoletePackets(b.unackedPackets.GetLeastUnacked())
}

func (b *BbrSender) GetMinRtt() time.Duration {
	if b.minRtt != 0 {
		return b.minRtt
	}
	return defaultInitialRTT
}

func (b *BbrSender) GetTargetCongestionWindow(gain float32) protocol.ByteCount {
	bdp := protocol.ByteCount(b.GetMinRtt().Nanoseconds()* 1000 * int64(b.BandwidthEstimate()))
	congestionWindow := protocol.ByteCount(gain) * bdp

	// BDP estimate will be zero if no bandwidth samples are available yet.
	if congestionWindow == 0 {
		congestionWindow = protocol.ByteCount(gain) * b.initialCongestionWindow
	}

	return utils.MaxByteCount(congestionWindow, b.minCongestionWindow)
}

func (b *BbrSender) ProbeRttCongestionWindow() protocol.ByteCount {
	if b.probeRttBasedOnBdp {
		return b.GetTargetCongestionWindow(moderateProbeRttMultiplier)
	}
	return b.minCongestionWindow
}

func (b *BbrSender) EnterStartupMode() {
	b.mode_ = STARTUP
	b.pacingGain = b.highGain
	b.congestionWindowGain = b.highCwndGain
}

func (b *BbrSender) EnterProbeBandwidthMode(now time.Time) {
	b.mode_ = PROBE_BW
	b.congestionWindowGain = b.congestionWindowGainConstant;

	// Pick a random offset for the gain cycle out of {0, 2..7} range. 1 is
	// excluded because in that case increased gain and decreased gain would not
	// follow each other.
	b.cycleCurrentOffset = int(rand.Uint64() % uint64(gainCycleLength - 1));
	if b.cycleCurrentOffset >= 1 {
		b.cycleCurrentOffset += 1;
	}

	b.lastCycleStart = now;
	b.pacingGain = pacingGain[b.cycleCurrentOffset];
}

func (b *BbrSender) DiscardLostPackets(lostPackets []LostPacket) {
	for _, packet := range lostPackets {
		b.sampler_.OnPacketLost(packet.packetNumber)
		if b.startupRateReductionMultiplier != 0 && b.mode_ == STARTUP {
			b.startupBytesLost += protocol.ByteCount(packet.bytesLost)
		}
	}
}

func (b *BbrSender) UpdateRoundTripCounter(lastSentPacket protocol.PacketNumber) bool {
	if lastSentPacket > b.currentRoundTripEnd {
		b.roundTripCount++
		b.currentRoundTripEnd = lastSentPacket
		return true
	}

	return false
}

func (b *BbrSender) UpdateBandwidthAndMinRtt(
	now time.Time,
	ackedPackets []AckedPacket) bool {
	sampleMinRtt := time.Duration(^uint(0))
	for _, packet := range ackedPackets {
		if packet.bytesAcked == 0 {
			// Skip acked packets with 0 in flight bytes when updating bandwidth.
			continue
		}
		var bandwidth_sample BandwidthSample = b.sampler_.OnPacketAcknowledged(now, packet.packetNumber)
		b.lastSampleIsAppLimited = bandwidth_sample.isAppLimited
		b.hasNonAppLimitedSample = b.hasNonAppLimitedSample || !bandwidth_sample.isAppLimited
		if bandwidth_sample.rtt != 0 {
			sampleMinRtt = utils.MinDuration(sampleMinRtt, bandwidth_sample.rtt)
		}

		if !bandwidth_sample.isAppLimited ||
			bandwidth_sample.bandwidth > b.BandwidthEstimate() {
			b.max_bandwidth_.Update(bandwidth_sample.bandwidth, b.roundTripCount)
		}
	}

	// If none of the RTT samples are valid, return immediately.
	if sampleMinRtt == time.Duration(^uint(0)) {
		return false
	}
	b.minRttSinceLastProbeRtt =
		utils.MinDuration(b.minRttSinceLastProbeRtt, sampleMinRtt)

	// Do not expire minRtt if none was ever available.
	minRttExpired :=
		(b.minRtt != 0) && now.After(b.minRttTimestamp.Add(minRttExpiry))

	if minRttExpired || sampleMinRtt < b.minRtt || b.minRtt == 0 {
		// QUIC_DVLOG(2) << "Min RTT updated, old value: " << minRtt
		// 			<< ", new value: " << sampleMinRtt
		// 			<< ", current time: " << now.ToDebuggingValue();

		if minRttExpired && b.ShouldExtendMinRttExpiry() {
			minRttExpired = false
		} else {
			b.minRtt = sampleMinRtt
		}
		b.minRttTimestamp = now
		// Reset since_last_probe_rtt fields.
		b.minRttSinceLastProbeRtt = time.Duration(^uint(0))
		b.appLimitedSinceLastProbeRtt = false
	}
	//DCHECK(b.minRtt != 0)

	return minRttExpired
}

func (b *BbrSender) ShouldExtendMinRttExpiry() bool {
	if b.probeRttDisabledIfAppLimited && b.appLimitedSinceLastProbeRtt {
		// Extend the current minRtt if we've been app limited recently.
		return true;
}
	minRttIncreasedSinceLastProbe :=
	float32(b.minRttSinceLastProbeRtt.Nanoseconds()) > float32(b.minRtt.Nanoseconds()) * similarMinRttThreshold;
	if b.probeRttSkippedIfSimilarRtt && b.appLimitedSinceLastProbeRtt &&
		!minRttIncreasedSinceLastProbe {
		// Extend the current minRtt if we've been app limited recently and an rtt
		// has been measured in that time that's less than 12.5% more than the
		// current minRtt.
		return true;
	}
	return false;
}

func (b *BbrSender) UpdateGainCyclePhase(now time.Time,
	prior_in_flight protocol.ByteCount,
	has_losses bool) {
	bytes_in_flight := b.unackedPackets.bytesInFlight
	// In most cases, the cycle is advanced after an RTT passes.
	should_advance_gain_cycling := now.Sub(b.lastCycleStart) > b.GetMinRtt();

	// If the pacing gain is above 1.0, the connection is trying to probe the
	// bandwidth by increasing the number of bytes in flight to at least
	// pacing_gain * BDP.  Make sure that it actually reaches the target, as long
	// as there are no losses suggesting that the buffers are not able to hold
	// that much.
	if b.pacingGain > 1.0 && !has_losses &&
		prior_in_flight < b.GetTargetCongestionWindow(b.pacingGain) {
		should_advance_gain_cycling = false;
	}

	// If pacing gain is below 1.0, the connection is trying to drain the extra
	// queue which could have been incurred by probing prior to it.  If the number
	// of bytes in flight falls down to the estimated BDP value earlier, conclude
	// that the queue has been successfully drained and exit this cycle early.
	if b.pacingGain < 1.0 && bytes_in_flight <= b.GetTargetCongestionWindow(1) {
		should_advance_gain_cycling = true;
	}

	if should_advance_gain_cycling {
		b.cycleCurrentOffset = (b.cycleCurrentOffset + 1) % gainCycleLength;
		b.lastCycleStart = now
		// Stay in low gain mode until the target BDP is hit.
		// Low gain mode will be exited immediately when the target BDP is achieved.
		if b.drainToTarget && b.pacingGain < 1 &&
			pacingGain[b.cycleCurrentOffset] == 1 &&
			bytes_in_flight > b.GetTargetCongestionWindow(1) {
		return
		}
		b.pacingGain = pacingGain[b.cycleCurrentOffset]
	}
}

func (b *BbrSender) CheckIfFullBandwidthReached() {
	if b.lastSampleIsAppLimited {
		return
	}

	target := float32(b.bandwidthAtLastRound) * startupGrowthTarget;
	if float32(b.BandwidthEstimate()) >= target {
		b.bandwidthAtLastRound = b.BandwidthEstimate();
		b.roundsWithoutBandwidthGain = 0
		if b.expireAckAggregationInStartup {
				// Expire old excess delivery measurements now that bandwidth increased.
				b.max_ack_height_.Reset(0, b.roundTripCount)
		}
		return
	}

	b.roundsWithoutBandwidthGain++;
	if (b.roundsWithoutBandwidthGain >= b.numStartupRtts) ||
		(b.exitStartupOnLoss && b.InRecovery()) {
		//DCHECK(hasNonAppLimitedSample);
		b.isAtFullBandwidth = true
	}
}

func (b *BbrSender) MaybeExitStartupOrDrain(now time.Time) {
	if b.mode_ == STARTUP && b.isAtFullBandwidth {
		b.mode_ = DRAIN;
		b.pacingGain = b.drainGain
		b.congestionWindowGain = b.highCwndGain
	}
	if b.mode_ == DRAIN &&
		b.unackedPackets.bytesInFlight <= b.GetTargetCongestionWindow(1) {
		b.EnterProbeBandwidthMode(now)
	}
}

func (b *BbrSender) MaybeEnterOrExitProbeRtt(now time.Time,
											is_round_start bool,
											min_rtt_expired bool) {
	if min_rtt_expired && !b.exitingQuiescence && b.mode_ != PROBE_RTT {
		b.mode_ = PROBE_RTT
		b.pacingGain = 1
		// Do not decide on the time to exit PROBE_RTT until the |bytes_in_flight|
		// is at the target small value.
		//b.exitProbeRttAt = 0
	}

	if b.mode_ == PROBE_RTT {
		b.sampler_.OnAppLimited();

		if b.exitProbeRttAt.IsZero() {
			// If the window has reached the appropriate size, schedule exiting
			// PROBE_RTT.  The CWND during PROBE_RTT is kMinimumCongestionWindow, but
			// we allow an extra packet since QUIC checks CWND before sending a
			// packet.
			if b.unackedPackets.bytesInFlight <
				b.ProbeRttCongestionWindow() + protocol.MaxReceivePacketSize {
				b.exitProbeRttAt = now.Add(probeRttTime)
				b.probeRttRoundPassed = false
			}
			} else {
			if is_round_start {
				b.probeRttRoundPassed = true
			}
			if (now.After(b.exitProbeRttAt) || now.Equal(b.exitProbeRttAt))  && b.probeRttRoundPassed {
				b.minRttTimestamp = now
				if !b.isAtFullBandwidth {
					b.EnterStartupMode()
				} else {
					b.EnterProbeBandwidthMode(now)
				}
			}
		}
	}

	b.exitingQuiescence = false
}

func (b *BbrSender) UpdateRecoveryState(
	lastAckedPacket protocol.PacketNumber,
	hasLosses bool,
	isRoundStart bool) {
	// Exit recovery when there are no losses for a round.
	if (hasLosses) {
		b.endRecoveryAt = b.lastSentPacket;
	}

	switch b.recoveryState {
		case NOT_IN_RECOVERY:
		// Enter conservation on the first loss.
		if (hasLosses) {
			b.recoveryState = CONSERVATION
			// This will cause the |recoveryWindow| to be set to the correct
			// value in CalculateRecoveryWindow().
			b.recoveryWindow = 0
			// Since the conservation phase is meant to be lasting for a whole
			// round, extend the current round as if it were started right now.
			b.currentRoundTripEnd = b.lastSentPacket
			if utils.FLAGS_bbr_app_limited_recovery && b.lastSampleIsAppLimited {
				//QUIC_RELOADABLE_FLAG_COUNT(quic_bbr_app_limited_recovery)
				b.isAppLimitedRecovery = true
			}
		}
		break

		case CONSERVATION:
		if isRoundStart {
			b.recoveryState = GROWTH;
		}

		case GROWTH:
		// Exit recovery if appropriate.
		if !hasLosses && lastAckedPacket > b.endRecoveryAt {
			b.recoveryState = NOT_IN_RECOVERY;
			b.isAppLimitedRecovery = false;
		}

		break
	}
	if (b.recoveryState != NOT_IN_RECOVERY && b.isAppLimitedRecovery) {
		b.sampler_.OnAppLimited();
	}
}

// TODO(ianswett): Move this logic into BandwidthSampler.
func (b *BbrSender) UpdateAckAggregationBytes(
	ack_time time.Time,
	newly_acked_bytes protocol.ByteCount) protocol.ByteCount {
	// Compute how many bytes are expected to be delivered, assuming max bandwidth
	// is correct.
	expectedBytesAcked :=
		protocol.ByteCount((b.max_bandwidth_.GetBest()>>3) * Bandwidth(ack_time.Sub(b.aggregationEpochStartTime).Seconds()))
	// Reset the current aggregation epoch as soon as the ack arrival rate is less
	// than or equal to the max bandwidth.
	if b.aggregationEpochBytes <= expectedBytesAcked {
		// Reset to start measuring a new aggregation epoch.
		b.aggregationEpochBytes = newly_acked_bytes
		b.aggregationEpochStartTime = ack_time
		return 0
	}

	// Compute how many extra bytes were delivered vs max bandwidth.
	// Include the bytes most recently acknowledged to account for stretch acks.
	b.aggregationEpochBytes += newly_acked_bytes
	b.max_ack_height_.Update(b.aggregationEpochBytes -expectedBytesAcked,
								b.roundTripCount)
	return b.aggregationEpochBytes - expectedBytesAcked
}

func (b *BbrSender) CalculatePacingRate() {
		if b.BandwidthEstimate() == 0 {
			return
		}

		target_rate := Bandwidth(b.pacingGain * float32(b.BandwidthEstimate()))
		if b.isAtFullBandwidth {
			b.pacingRate = target_rate
			return
		}

		// Pace at the rate of initial_window / RTT as soon as RTT measurements are
		// available.
		if b.pacingRate==0 && b.rttStats.minRTT != 0 {
			b.pacingRate = BandwidthFromDelta(b.initialCongestionWindow, b.rttStats.minRTT)
			return
		}
		// Slow the pacing rate in STARTUP once loss has ever been detected.
		hasEverDetectedLoss := b.endRecoveryAt > 0;
		if b.slowerStartup && hasEverDetectedLoss &&
			b.hasNonAppLimitedSample {
			b.pacingRate = Bandwidth(startupAfterLossGain * float32(b.BandwidthEstimate()))
			return;
		}

		// Slow the pacing rate in STARTUP by the bytesLost / CWND.
		if b.startupRateReductionMultiplier != 0 && hasEverDetectedLoss &&
			b.hasNonAppLimitedSample {
			b.pacingRate =
				Bandwidth(1 - (float32(b.startupBytesLost) * float32(b.startupRateReductionMultiplier) * 1.0 /
					float32(b.congestionWindow)))*
				target_rate
			// Ensure the pacing rate doesn't drop below the startup growth target times
			// the bandwidth estimate.
			b.pacingRate =
				Bandwidth(utils.MaxFloat32(float32(b.pacingRate), startupGrowthTarget * float32(b.BandwidthEstimate())))
			return
		}

		// Do not decrease the pacing rate during startup.
		b.pacingRate = Bandwidth(utils.MaxUint64(uint64(b.pacingRate), uint64(target_rate)))
}

func (b *BbrSender) CalculateCongestionWindow(bytesAcked protocol.ByteCount,
										excessAcked protocol.ByteCount) {
		if b.mode_ == PROBE_RTT {
			return
		}

		var target_window protocol.ByteCount =
			b.GetTargetCongestionWindow(b.congestionWindowGain);
		if b.isAtFullBandwidth {
			// Add the max recently measured ack aggregation to CWND.
			target_window += b.max_ack_height_.GetBest()
		} else if b.enableAckAggregationDuringStartup {
			// Add the most recent excess acked.  Because CWND never decreases in
			// STARTUP, this will automatically create a very localized max filter.
			target_window += excessAcked
		}

		// Instead of immediately setting the target CWND as the new one, BBR grows
		// the CWND towards |target_window| by only increasing it |bytesAcked| at a
		// time.
		addBytesAcked :=
			!utils.FLAGS_bbr_no_bytes_acked_in_startup_recovery ||
			!b.InRecovery()
		if b.isAtFullBandwidth {
			b.congestionWindow =
				utils.MinByteCount(target_window, b.congestionWindow + bytesAcked);
		} else if addBytesAcked &&
						(b.congestionWindow < target_window ||
					b.sampler_.totalBytesAcked < b.initialCongestionWindow) {
			// If the connection is not yet out of startup phase, do not decrease the
			// window.
			b.congestionWindow = b.congestionWindow + bytesAcked
		}

		// Enforce the limits on the congestion window.
		b.congestionWindow = utils.MaxByteCount(b.congestionWindow, b.minCongestionWindow)
		b.congestionWindow = utils.MinByteCount(b.congestionWindow, b.maxCongestionWindow)
}

func (b *BbrSender) CalculateRecoveryWindow(
	bytesAcked protocol.ByteCount,
	bytesLost protocol.ByteCount) {
		if b.rateBasedStartup && b.mode_ == STARTUP {
			return
		}

		if b.recoveryState == NOT_IN_RECOVERY {
			return
		}

		// Set up the initial recovery window.
		if b.recoveryWindow == 0 {
			b.recoveryWindow = b.unackedPackets.bytesInFlight + bytesAcked
			b.recoveryWindow = utils.MaxByteCount(b.minCongestionWindow, b.recoveryWindow)
			return
		}

		// Remove losses from the recovery window, while accounting for a potential
		// integer underflow.
		if b.recoveryWindow >= bytesLost {
			b.recoveryWindow = b.recoveryWindow - bytesLost
		} else {
			b.recoveryWindow = protocol.MaxSegmentSize
		}

		// In CONSERVATION mode, just subtracting losses is sufficient.  In GROWTH,
		// release additional |bytesAcked| to achieve a slow-start-like behavior.
		if (b.recoveryState == GROWTH) {
			b.recoveryWindow += bytesAcked;
		}

		// Sanity checks.  Ensure that we always allow to send at least an MSS or
		// |bytesAcked| in response, whichever is larger.
		b.recoveryWindow = utils.MaxByteCount(
			b.recoveryWindow, b.unackedPackets.bytesInFlight + bytesAcked);
		if utils.FLAGS_bbr_one_mss_conservation {
			b.recoveryWindow =
			utils.MaxByteCount(b.recoveryWindow,
							b.unackedPackets.bytesInFlight + protocol.MaxSegmentSize)
		}
		b.recoveryWindow = utils.MaxByteCount(b.minCongestionWindow, b.recoveryWindow)
}

func (b *BbrSender) OnApplicationLimited(bytesInFlight protocol.ByteCount) {
		if bytesInFlight >= b.GetCongestionWindow() {
			return
		}
		if b.flexibleAppLimited && b.IsPipeSufficientlyFull() {
			return
		}

		b.appLimitedSinceLastProbeRtt = true
		b.sampler_.OnAppLimited()
		// QUIC_DVLOG(2) << "Becoming application limited. Last sent packet: "
		// 				<< lastSentPacket << ", CWND: " << GetCongestionWindow();
}

