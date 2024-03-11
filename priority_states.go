package quic

// PRIO_PACKS_TAG
// TODOME: maybe add possibility of more specifc prio handling
// e.g. for different packet types
var (
	PrioRetryPacket           StreamPriority = 1
	PrioConnectionClosePacket StreamPriority = 1
	PrioCoalescedPacket       StreamPriority = 1
	PrioAppendPacket          StreamPriority = 1
	PrioProbePacket           StreamPriority = 1
	PrioMTUProbePacket        StreamPriority = 1
	PrioLongHeaderPacket      StreamPriority = 1
)
