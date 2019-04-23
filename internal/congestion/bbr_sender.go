package congestion

// src from https://quiche.googlesource.com/quiche.git/+/66dea072431f94095dfc3dd2743cb94ef365f7ef/quic/core/congestion_control/bbr_sender.cc

import (
	"time"

	"math"

	"math/rand"

	"github.com/lucas-clemente/quic-go/internal/protocol"
)

var (
	// Default maximum packet size used in the Linux TCP implementation.
	// Used in QUIC for congestion window computations in bytes.
	MaxSegmentSize = protocol.DefaultTCPMSS

	// Constants based on TCP defaults.
	// The minimum CWND to ensure delayed acks don't reduce bandwidth measurements.
	// Does not inflate the pacing rate.
	defaultMiniumCongestionWindow = 4 * protocol.DefaultTCPMSS

	// The gain used for the STARTUP, equal to 2/ln(2).
	defaultHighGain = 2.885

	// The newly derived gain for STARTUP, equal to 4 * ln(2)
	derivedHighGain = 2.773

	// The newly derived CWND gain for STARTUP, 2.
	derivedHighCWNDGain = 2.773

	// The gain used in STARTUP after loss has been detected.
	// 1.5 is enough to allow for 25% exogenous loss and still observe a 25% growth
	// in measured bandwidth.
	StartupAfterLossGain = 1.5

	// The cycle of gains used during the PROBE_BW stage.
	pacingGain = []float64{1.25, 0.75, 1, 1, 1, 1, 1, 1}

	// The length of the gain cycle.
	gainCycleLength = len(pacingGain)

	// The size of the bandwidth filter window, in round-trips.
	bandwidthWindowSize = len(pacingGain) + 2

	// The time after which the current min_rtt value expires.
	minRttExpiry = 10 * time.Second

	// The minimum time the connection can spend in PROBE_RTT mode.
	minProbeRttTime = 200 * time.Millisecond

	// If the bandwidth does not increase by the factor of |startupGrowthTarget|
	// within |roundTripsWithoutGrowthBeforeExitingStartup| rounds, the connection
	// will exit the STARTUP mode.
	startGrowthTarget                           = 1.25
	roundTripsWithoutGrowthBeforeExitingStartup = int64(3)

	// Coefficient of target congestion window to use when basing PROBE_RTT on BDP.
	moderateProbeRttMultiplier = 0.75

	// Coefficient to determine if a new RTT is sufficiently similar to min_rtt that
	// we don't need to enter PROBE_RTT.
	similarMinRttThreshold = 1.125

	// If the bandwidth does not increase by the factor of |kStartupGrowthTarget|
	// within |kRoundTripsWithoutGrowthBeforeExitingStartup| rounds, the connection
	// will exit the STARTUP mode.
	startupGrowthTarget = 1.25

	// The maximum outgoing packet size allowed.
	// The maximum packet size of any QUIC packet over IPv6, based on ethernet's max
	// size, minus the IP and UDP headers. IPv6 has a 40 byte header, UDP adds an
	// additional 8 bytes.  This is a total overhead of 48 bytes.  Ethernet's
	// max packet size is 1500 bytes,  1500 - 48 = 1452.
	MaxOutgoingPacketSize = protocol.ByteCount(1452)

	// The minimum time the connection can spend in PROBE_RTT mode.
	ProbeRttTime = time.Millisecond * 200

	// Coefficient of target congestion window to use when basing PROBE_RTT on BDP.
	ModerateProbeRttMultiplier = 0.75
)

type bbrMode int

const (
	// Startup phase of the connection.
	STARTUP = iota
	// After achieving the highest possible bandwidth during the startup, lower
	// the pacing rate in order to drain the queue.
	DRAIN
	// Cruising mode.
	PROBE_BW
	// Temporarily slow down sending in order to empty the buffer and measure
	// the real minimum RTT.
	PROBE_RTT
)

type bbrRecoveryState int

const (
	// Do not limit.
	NOT_IN_RECOVERY = iota

	// Allow an extra outstanding byte for each byte acknowledged.
	CONSERVATION

	// Allow two extra outstanding bytes for each byte acknowledged (slow
	// start).
	GROWTH
)

type bbrSender struct {
	mode                          bbrMode
	clock                         Clock
	rttStats                      *RTTStats
	initialCongestionWindow       protocol.ByteCount
	maxCongestionDinwow           protocol.ByteCount
	minCongestionWindow           protocol.ByteCount
	congestionWindow              protocol.ByteCount
	recoveryWindow                protocol.ByteCount
	lastSendPacket                protocol.PacketNumber
	bytesInFlight                 protocol.ByteCount
	endRecoveryAt                 protocol.PacketNumber
	aggregationEpochStartTime     time.Time
	aggregationEpochBytes         protocol.ByteCount
	rateBasedStartup              bool
	recoveryState                 bbrRecoveryState
	pacingGain                    float64
	congestionWindowGain          float64
	congestionWindowGainConst     float64
	highGain                      float64
	highCwndGain                  float64
	drainGain                     float64
	cycleCurrentOffset            int
	lastCycleStart                time.Time
	drainToTarget                 bool
	currentRoundTripEnd           protocol.PacketNumber
	roundTripCount                int64
	alwaysGetBwSampleWhenAcked    bool
	sampler                       *BandwidthSampler
	lastSampleIsAppLimited        bool
	hasNoAppLimitedSample         bool
	isAppLimitedRecovery          bool
	minRtt                        time.Duration
	minRttSinceLastProbeRtt       time.Duration
	minRttTimestamp               time.Time
	maxBandwidth                  *WindowedFilter
	maxAckHeight                  *WindowedFilter
	appLimitedSinceLastProbeRtt   bool
	isAtFullBandwidth             bool
	bandwidthAtLastRound          Bandwidth
	roundsWithoutBandwidthGain    int64
	expireAckAggregationInStartup bool
	numStartupRtts                int64
	exitStartupOnLoss             bool

	// Set to true upon exiting quiescence.
	exitingQuiescence bool

	// Time at which PROBE_RTT has to be exited.  Setting it to zero indicates
	// that the time is yet unknown as the number of packets in flight has not
	// reached the required value.
	exitProbeRttAt time.Time

	// Indicates whether a round-trip has passed since PROBE_RTT became active.
	probeRttRoundPassed bool

	// If true, use a CWND of 0.75*BDP during probe_rtt instead of 4 packets.
	probeRttBasedOnBdp bool

	// When non-zero, decreases the rate in STARTUP by the total number of bytes
	// lost in STARTUP divided by CWND.
	startupRateReductionMultiplier int64

	// Sum of bytes lost in STARTUP.
	startupBytesLost protocol.ByteCount

	// The current pacing rate of the connection.
	pacingRate Bandwidth

	// When true, pace at 1.5x and disable packet conservation in STARTUP.
	slowerStartup bool

	// When true, add the most recent ack aggregation measurement during STARTUP.
	enableAckAggerationDuringStartup bool
}

func NewBBRSender(clock Clock, rttStats *RTTStats, initialCongestionWindow, initialMaxCongestionWindow protocol.ByteCount) SendAlgorithmWithDebugInfo {
	return &bbrSender{
		mode:                      STARTUP,
		clock:                     clock,
		rttStats:                  rttStats,
		initialCongestionWindow:   initialCongestionWindow,
		maxCongestionDinwow:       initialMaxCongestionWindow,
		minCongestionWindow:       defaultMinimumCongestionWindow,
		congestionWindow:          initialCongestionWindow,
		highGain:                  defaultHighGain,
		highCwndGain:              defaultHighGain,
		drainGain:                 1.0 / defaultHighGain,
		pacingGain:                1.0,
		congestionWindowGain:      1.0,
		congestionWindowGainConst: 2.0,
		recoveryState:             NOT_IN_RECOVERY,
		recoveryWindow:            initialMaxCongestionWindow,
		sampler:                   NewBandwidthSampler(),
		maxBandwidth:              NewWindowedFilter(int64(bandwidthWindowSize)),
		maxAckHeight:              NewWindowedFilter(int64(bandwidthWindowSize)),
		minRtt:                    InfiniteRTT,
		minRttSinceLastProbeRtt:   InfiniteRTT,
		numStartupRtts:            roundTripsWithoutGrowthBeforeExitingStartup,
	}
}

func (b *bbrSender) TimeUntilSend(bytesInFlight protocol.ByteCount) time.Duration {
	return time.Microsecond
}

func (b *bbrSender) OnPacketSent(sentTime time.Time, bytesInFlight protocol.ByteCount, packetNumber protocol.PacketNumber, bytes protocol.ByteCount, isRetransmittable bool) {
	b.lastSendPacket = packetNumber
	b.bytesInFlight = bytesInFlight

	if bytesInFlight == 0 && b.sampler.isAppLimited {
		b.exitingQuiescence = true
	}

	if b.aggregationEpochStartTime.IsZero() {
		b.aggregationEpochStartTime = sentTime
	}

	b.sampler.OnPacketSent(sentTime, packetNumber, bytes, bytesInFlight, isRetransmittable)
}

func (b *bbrSender) GetCongestionWindow() protocol.ByteCount {
	if b.mode == PROBE_RTT {
		return b.ProbeRttCongestionWindow()
	}

	if b.InRecovery() && !(b.rateBasedStartup && b.mode == STARTUP) {
		if b.congestionWindow < b.recoveryWindow {
			return b.congestionWindow
		} else {
			return b.recoveryWindow
		}
	}

	return b.congestionWindow
}

func (b *bbrSender) MaybeExitSlowStart() {

}

func (b *bbrSender) OnPacketAcked(number protocol.PacketNumber, ackedBytes protocol.ByteCount, priorInFlight protocol.ByteCount, eventTime time.Time) {
	b.OnCongestionEvent(number, ackedBytes, 0, priorInFlight, eventTime)
}

func (b *bbrSender) OnPacketLost(number protocol.PacketNumber, lostBytes protocol.ByteCount, priorInFlight protocol.ByteCount) {
	b.OnCongestionEvent(number, 0, lostBytes, priorInFlight, b.clock.Now())
}

func (b *bbrSender) OnCongestionEvent(number protocol.PacketNumber, ackedBytes protocol.ByteCount, lostBytes protocol.ByteCount, priorInFlight protocol.ByteCount, eventTime time.Time) {
	isRoundStart, minRttExpired := false, false

	if lostBytes > 0 {
		b.DiscardLostPackets(number, lostBytes)
	}

	// Input the new data into the BBR model of the connection.
	var excessAcked protocol.ByteCount
	if ackedBytes > 0 {
		isRoundStart = b.UpdateRoundTripCounter(number)
		minRttExpired = b.UpdateBandwidthAndMinRtt(eventTime, number, ackedBytes)
		b.UpdateRecoveryState(number, false, isRoundStart)

		excessAcked = b.UpdateAckAggregationBytes(eventTime, ackedBytes)
	}

	if b.mode == PROBE_BW {
		b.UpdateGainCyclePhase(eventTime, priorInFlight, false)
	}

	// Handle logic specific to STARTUP and DRAIN modes.
	if isRoundStart && !b.isAtFullBandwidth {
		b.CheckIfFullBandwidthReached()
	}
	b.MaybeExitStartupOrDrain(eventTime)

	// Handle logic specific to PROBE_RTT.
	b.MaybeEnterOrExitProbeRtt(eventTime, isRoundStart, minRttExpired)

	// After the model is updated, recalculate the pacing rate and congestion
	// window.
	b.CalculatePacingRate()
	b.CalculateCongestionWindow(ackedBytes, excessAcked)
	b.CalculateRecoveryWindow(ackedBytes, lostBytes)

	// Cleanup internal state.
	b.sampler.RemoveObsoletePackets(number)
}

func (b *bbrSender) SetNumEmulatedConnections(n int) {

}

func (b *bbrSender) OnRetransmissionTimeout(packetsRetransmitted bool) {

}

func (b *bbrSender) OnConnectionMigration() {

}

// Experiments
func (b *bbrSender) SetSlowStartLargeReduction(enabled bool) {

}

func (b *bbrSender) BandwidthEstimate() Bandwidth {
	return Bandwidth(b.maxBandwidth.GetBest())
}

func (b *bbrSender) HybridSlowStart() *HybridSlowStart {
	return nil
}

func (b *bbrSender) SlowstartThreshold() protocol.ByteCount {
	return 0
}

func (b *bbrSender) RenoBeta() float32 {
	return 0.0
}

func (b *bbrSender) InRecovery() bool {
	return b.recoveryState != NOT_IN_RECOVERY
}

func (b *bbrSender) InSlowStart() bool {
	return b.mode == STARTUP
}

func (b *bbrSender) ShouldSendProbingPacket() bool {
	return b.pacingGain <= 1
}

func (b *bbrSender) UpdateRoundTripCounter(lastAckedPacket protocol.PacketNumber) bool {
	if lastAckedPacket > b.currentRoundTripEnd {
		b.currentRoundTripEnd = lastAckedPacket
		b.roundTripCount++
		if b.rttStats != nil && b.InSlowStart() {
			// TODO: ++stats_->slowstart_num_rtts;
		}
		return true
	}
	return false
}

func (b *bbrSender) UpdateBandwidthAndMinRtt(now time.Time, lastAckedPacket protocol.PacketNumber, ackedBytes protocol.ByteCount) bool {
	if !b.alwaysGetBwSampleWhenAcked && ackedBytes == 0 {
		return false
	}

	sample := b.sampler.OnPacketAcked(now, lastAckedPacket, ackedBytes)
	if b.alwaysGetBwSampleWhenAcked && !sample.stateAtSend.isValid {
		return false
	}

	b.lastSampleIsAppLimited = sample.stateAtSend.isAppLimited
	b.hasNoAppLimitedSample = !sample.stateAtSend.isAppLimited || b.hasNoAppLimitedSample

	sampleMinRtt := InfiniteRTT
	if sample.rtt > 0 {
		sampleMinRtt = minRtt(sampleMinRtt, sample.rtt)
	}

	if !sample.stateAtSend.isAppLimited || sample.bandwidth > b.BandwidthEstimate() {
		b.maxBandwidth.Update(int64(sample.bandwidth), b.roundTripCount)
	}

	// If none of the RTT samples are valid, return immediately.
	if sampleMinRtt == InfiniteRTT {
		return false
	}
	b.minRttSinceLastProbeRtt = minRtt(b.minRttSinceLastProbeRtt, sampleMinRtt)

	// Do not expire min_rtt if none was ever available.
	minRttExpired := b.minRtt != InfiniteRTT && (now.After(b.minRttTimestamp.Add(minRttExpiry)))
	if minRttExpired || sampleMinRtt < b.minRtt || b.minRtt == InfiniteRTT {
		if minRttExpired && b.ShouldExtendMinRttExpiry() {
			minRttExpired = false
		} else {
			b.minRtt = sampleMinRtt
		}
		b.minRttTimestamp = now
		b.minRttSinceLastProbeRtt = InfiniteRTT
		b.appLimitedSinceLastProbeRtt = false
	}

	return minRttExpired
}

func (b *bbrSender) ShouldExtendMinRttExpiry() bool {
	return false
}

func (b *bbrSender) DiscardLostPackets(number protocol.PacketNumber, lostBytes protocol.ByteCount) {
	b.sampler.OnPacketLost(number)
	if b.mode == STARTUP {
		if b.rttStats != nil {
			// TODO: slow start.
		}
		if b.startupRateReductionMultiplier != 0 {
			b.startupBytesLost += lostBytes
		}
	}
}

func (b *bbrSender) UpdateRecoveryState(lastAckedPacket protocol.PacketNumber, hasLosses, isRoundStart bool) {
	if !hasLosses {
		b.endRecoveryAt = b.lastSendPacket
	}

	switch b.recoveryState {
	case NOT_IN_RECOVERY:
		if hasLosses {
			b.recoveryState = CONSERVATION
			b.recoveryWindow = 0
			b.currentRoundTripEnd = b.lastSendPacket
			if false && b.lastSampleIsAppLimited {
				b.isAppLimitedRecovery = true
			}
		}
	case CONSERVATION:
		if isRoundStart {
			b.recoveryState = GROWTH
		}

		if !hasLosses && b.lastSendPacket > b.endRecoveryAt {
			b.recoveryState = NOT_IN_RECOVERY
			b.isAppLimitedRecovery = false
		}
	case GROWTH:
		if !hasLosses && b.lastSendPacket > b.endRecoveryAt {
			b.recoveryState = NOT_IN_RECOVERY
			b.isAppLimitedRecovery = false
		}
	}
	if b.recoveryState != NOT_IN_RECOVERY && b.isAppLimitedRecovery {
		b.sampler.OnAppLimited()
	}
}

func (b *bbrSender) UpdateAckAggregationBytes(ackTime time.Time, ackedBytes protocol.ByteCount) protocol.ByteCount {
	// Compute how many bytes are expected to be delivered, assuming max bandwidth
	// is correct.
	expectedAckedBytes := protocol.ByteCount(b.maxBandwidth.GetBest()) * protocol.ByteCount((ackTime.Sub(b.aggregationEpochStartTime)))
	if b.aggregationEpochBytes <= expectedAckedBytes {
		b.aggregationEpochBytes = ackedBytes
		b.aggregationEpochStartTime = ackTime
		return 0
	}

	b.aggregationEpochBytes += ackedBytes
	b.maxAckHeight.Update(int64(b.aggregationEpochBytes-expectedAckedBytes), b.roundTripCount)
	return b.aggregationEpochBytes - expectedAckedBytes
}

func (b *bbrSender) UpdateGainCyclePhase(now time.Time, priorInFlight protocol.ByteCount, hasLossed bool) {
	bytesInFlight := b.bytesInFlight
	shouldAdvanceGainCycling := now.Sub(b.lastCycleStart) > b.GetMinRtt()

	if b.pacingGain > 1.0 && !hasLossed && priorInFlight < b.GetTargetCongestionWindow(b.pacingGain) {
		shouldAdvanceGainCycling = false
	}

	if b.pacingGain < 1.0 && bytesInFlight <= b.GetTargetCongestionWindow(1.0) {
		shouldAdvanceGainCycling = true
	}

	if shouldAdvanceGainCycling {
		b.cycleCurrentOffset = (b.cycleCurrentOffset + 1) % gainCycleLength
		b.lastCycleStart = now

		if b.drainToTarget && b.pacingGain < 1.0 && pacingGain[b.cycleCurrentOffset] == 1.0 && bytesInFlight > b.GetTargetCongestionWindow(1.0) {
			return
		}
		b.pacingGain = pacingGain[b.cycleCurrentOffset]
	}
}

func (b *bbrSender) GetTargetCongestionWindow(gain float64) protocol.ByteCount {
	bdp := protocol.ByteCount(b.GetMinRtt()) * protocol.ByteCount(b.BandwidthEstimate())
	congestionWindow := protocol.ByteCount(gain * float64(bdp))

	if congestionWindow == 0 {
		congestionWindow = protocol.ByteCount(gain * float64(b.initialCongestionWindow))
	}

	return maxByteCount(congestionWindow, b.minCongestionWindow)
}

func (b *bbrSender) CheckIfFullBandwidthReached() {
	if b.lastSampleIsAppLimited {
		return
	}

	target := Bandwidth(float64(b.bandwidthAtLastRound) * startupGrowthTarget)
	if b.BandwidthEstimate() >= target {
		b.bandwidthAtLastRound = b.BandwidthEstimate()
		b.roundsWithoutBandwidthGain = 0
		if b.expireAckAggregationInStartup {
			// Expire old excess delivery measurements now that bandwidth increased.
			b.maxAckHeight.Reset(0, b.roundTripCount)
		}
		return
	}

	b.roundsWithoutBandwidthGain++
	if b.roundsWithoutBandwidthGain >= b.numStartupRtts || b.exitStartupOnLoss && b.InRecovery() {
		b.isAtFullBandwidth = true
	}
}

func (b *bbrSender) MaybeExitStartupOrDrain(now time.Time) {
	if b.mode == STARTUP && b.isAtFullBandwidth {
		b.OnExitStartup(now)
		b.mode = DRAIN
		b.pacingGain = b.drainGain
		b.congestionWindowGain = b.highCwndGain
	}
	if b.mode == DRAIN && b.bytesInFlight <= b.GetTargetCongestionWindow(1) {
		b.EnterProbeBandwidthMode(now)
	}
}

func (b *bbrSender) EnterProbeBandwidthMode(now time.Time) {
	b.mode = PROBE_BW
	b.congestionWindowGain = b.congestionWindowGainConst

	// Pick a random offset for the gain cycle out of {0, 2..7} range. 1 is
	// excluded because in that case increased gain and decreased gain would not
	// follow each other.
	b.cycleCurrentOffset = rand.Intn(gainCycleLength - 1)
	if b.cycleCurrentOffset >= 1 {
		b.cycleCurrentOffset += 1
	}

	b.lastCycleStart = now
	b.pacingGain = pacingGain[b.cycleCurrentOffset]
}

func (b *bbrSender) MaybeEnterOrExitProbeRtt(now time.Time, isRoundStart, minRttExpired bool) {
	if minRttExpired && !b.exitingQuiescence && b.mode != PROBE_RTT {
		if b.InSlowStart() {
			b.OnExitStartup(now)
		}
		b.mode = PROBE_RTT
		b.pacingGain = 1.0
		// Do not decide on the time to exit PROBE_RTT until the |bytes_in_flight|
		// is at the target small value.
		b.exitProbeRttAt = time.Time{}
	}

	if b.mode == PROBE_RTT {
		b.sampler.OnAppLimited()

		if b.exitProbeRttAt.IsZero() {
			// If the window has reached the appropriate size, schedule exiting
			// PROBE_RTT.  The CWND during PROBE_RTT is kMinimumCongestionWindow, but
			// we allow an extra packet since QUIC checks CWND before sending a
			// packet.
			if b.bytesInFlight < b.ProbeRttCongestionWindow()+MaxOutgoingPacketSize {
				b.exitProbeRttAt = now.Add(ProbeRttTime)
				b.probeRttRoundPassed = false
			}
		} else {
			if isRoundStart {
				b.probeRttRoundPassed = true
			}
			if !now.Before(b.exitProbeRttAt) && b.probeRttRoundPassed {
				b.minRttTimestamp = now
				if !b.isAtFullBandwidth {
					b.EnterStartupMode(now)
				} else {
					b.EnterProbeBandwidthMode(now)
				}
			}
		}
	}
	b.exitingQuiescence = false
}

func (b *bbrSender) ProbeRttCongestionWindow() protocol.ByteCount {
	if b.probeRttBasedOnBdp {
		return b.GetTargetCongestionWindow(ModerateProbeRttMultiplier)
	} else {
		return b.minCongestionWindow
	}
}

func (b *bbrSender) EnterStartupMode(now time.Time) {
	if b.rttStats != nil {
		// TODO: slow start.
	}
	b.mode = STARTUP
	b.pacingGain = b.highGain
	b.congestionWindowGain = b.highCwndGain
}

func (b *bbrSender) OnExitStartup(now time.Time) {
	if b.rttStats == nil {
		return
	}
	// TODO: slow start.
}

func (b *bbrSender) CalculatePacingRate() {
	if b.BandwidthEstimate() == 0 {
		return
	}

	targetRate := Bandwidth(b.pacingGain * float64(b.BandwidthEstimate()))
	if b.isAtFullBandwidth {
		b.pacingRate = targetRate
		return
	}

	// Pace at the rate of initial_window / RTT as soon as RTT measurements are
	// available.
	if b.pacingRate == 0 && b.rttStats.MinRTT() > 0 {
		b.pacingRate = BandwidthFromDelta(b.initialCongestionWindow, b.rttStats.MinRTT())
		return
	}
	// Slow the pacing rate in STARTUP once loss has ever been detected.
	hasEverDetectedLoss := b.endRecoveryAt > 0
	if b.slowerStartup && hasEverDetectedLoss && b.hasNoAppLimitedSample {
		b.pacingRate = Bandwidth(StartupAfterLossGain * float64(b.BandwidthEstimate()))
		return
	}

	// Slow the pacing rate in STARTUP by the bytes_lost / CWND.
	if b.startupRateReductionMultiplier != 0 && hasEverDetectedLoss && b.hasNoAppLimitedSample {
		b.pacingRate = Bandwidth((1.0 - (float64(b.startupBytesLost) * float64(b.startupRateReductionMultiplier) / float64(b.congestionWindow))) * float64(targetRate))
		// Ensure the pacing rate doesn't drop below the startup growth target times
		// the bandwidth estimate.
		b.pacingRate = maxBandwidth(b.pacingRate, Bandwidth(StartupAfterLossGain*float64(b.BandwidthEstimate())))
		return
	}

	// Do not decrease the pacing rate during startup.
	b.pacingRate = maxBandwidth(b.pacingRate, targetRate)
}

func (b *bbrSender) CalculateCongestionWindow(ackedBytes, excessAcked protocol.ByteCount) {
	if b.mode == PROBE_RTT {
		return
	}

	targetWindow := b.GetTargetCongestionWindow(b.congestionWindowGain)
	if b.isAtFullBandwidth {
		// Add the max recently measured ack aggregation to CWND.
		targetWindow += protocol.ByteCount(b.maxAckHeight.GetBest())
	} else if b.enableAckAggerationDuringStartup {
		// Add the most recent excess acked.  Because CWND never decreases in
		// STARTUP, this will automatically create a very localized max filter.
		targetWindow += excessAcked
	}

	// Instead of immediately setting the target CWND as the new one, BBR grows
	// the CWND towards |target_window| by only increasing it |bytes_acked| at a
	// time.
	addBytesAcked := true || !b.InRecovery()
	if b.isAtFullBandwidth {
		b.congestionWindow = minByteCount(targetWindow, b.congestionWindow+ackedBytes)
	} else if addBytesAcked && (b.congestionWindow < targetWindow || b.sampler.totalBytesAcked < b.initialCongestionWindow) {
		// If the connection is not yet out of startup phase, do not decrease the
		// window.
		b.congestionWindow += ackedBytes
	}

	// Enforce the limits on the congestion window.
	b.congestionWindow = maxByteCount(b.congestionWindow, b.minCongestionWindow)
	b.congestionWindow = minByteCount(b.congestionWindow, b.maxCongestionDinwow)
}

func (b *bbrSender) CalculateRecoveryWindow(ackedBytes, lostBytes protocol.ByteCount) {
	if b.rateBasedStartup && b.mode == STARTUP {
		return
	}

	if b.recoveryState == NOT_IN_RECOVERY {
		return
	}

	// Set up the initial recovery window.
	if b.recoveryWindow == 0 {
		b.recoveryWindow = maxByteCount(b.bytesInFlight+ackedBytes, b.minCongestionWindow)
		return
	}

	// Remove losses from the recovery window, while accounting for a potential
	// integer underflow.
	if b.recoveryWindow >= lostBytes {
		b.recoveryWindow -= lostBytes
	} else {
		b.recoveryWindow = MaxSegmentSize
	}

	// In CONSERVATION mode, just subtracting losses is sufficient.  In GROWTH,
	// release additional |bytes_acked| to achieve a slow-start-like behavior.
	if b.recoveryState == GROWTH {
		b.recoveryWindow += ackedBytes
	}

	// Sanity checks.  Ensure that we always allow to send at least an MSS or
	// |bytes_acked| in response, whichever is larger.
	b.recoveryWindow = maxByteCount(b.recoveryWindow, b.bytesInFlight+ackedBytes)
	b.recoveryWindow = maxByteCount(b.recoveryWindow, b.minCongestionWindow)
}

func (b *bbrSender) GetMinRtt() time.Duration {
	if b.minRtt != InfiniteRTT {
		return b.minRtt
	} else {
		return b.rttStats.MinRTT()
	}
}

func minRtt(a, b time.Duration) time.Duration {
	if a < b {
		return a
	} else {
		return b
	}
}

func minBandwidth(a, b Bandwidth) Bandwidth {
	if a < b {
		return a
	} else {
		return b
	}
}

func maxBandwidth(a, b Bandwidth) Bandwidth {
	if a > b {
		return a
	} else {
		return b
	}
}

func maxByteCount(a, b protocol.ByteCount) protocol.ByteCount {
	if a > b {
		return a
	} else {
		return b
	}
}

func minByteCount(a, b protocol.ByteCount) protocol.ByteCount {
	if a < b {
		return a
	} else {
		return b
	}
}

var (
	InfiniteRTT = time.Duration(math.MaxInt64)
)
