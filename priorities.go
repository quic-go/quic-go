package quic

import "github.com/danielpfeifer02/quic-go-prio-packs/internal/protocol"

var (
	NoPriority   protocol.StreamPriority = -1
	LowPriority  protocol.StreamPriority = 0
	HighPriority protocol.StreamPriority = 1
)
