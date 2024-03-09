package quic

var (
	PrioRetryPacket           int8 = 1
	PrioConnectionClosePacket int8 = 1
	PrioCoalescedPacket       int8 = 1
	PrioAppendPacket          int8 = 1
	PrioProbePacket           int8 = 1
	PrioMTUProbePacket        int8 = 1
	PrioLongHeaderPacket      int8 = 1
)
