package congestion

import (
	"github.com/lucas-clemente/quic-go/internal/protocol"
)

func GetCongestionControlerFromConfig(rttStats *RTTStats, congestionConfig protocol.CongestionControlAlgorithm) SendAlgorithmWithDebugInfo {
	var congestionAlgorithm SendAlgorithmWithDebugInfo
	switch congestionConfig {
	case protocol.CUBIC:
		congestionAlgorithm = NewCubicSender(
			DefaultClock{},
			rttStats,
			false,
			protocol.InitialCongestionWindow,
			protocol.DefaultMaxCongestionWindow,
		)
	case protocol.RENO:
		congestionAlgorithm = NewCubicSender(
			DefaultClock{},
			rttStats,
			true,
			protocol.InitialCongestionWindow,
			protocol.DefaultMaxCongestionWindow,
		)
	default:
		congestionAlgorithm = NewCubicSender(
			DefaultClock{},
			rttStats,
			false, /* don't use reno since chromium doesn't (why?) */
			protocol.InitialCongestionWindow,
			protocol.DefaultMaxCongestionWindow,
		)
	}
	return congestionAlgorithm
}
