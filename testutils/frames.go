package testutils

import "github.com/Noooste/quic-go/internal/wire"

type (
	Frame                   = wire.Frame
	AckFrame                = wire.AckFrame
	ConnectionCloseFrame    = wire.ConnectionCloseFrame
	CryptoFrame             = wire.CryptoFrame
	DataBlockedFrame        = wire.DataBlockedFrame
	HandshakeDoneFrame      = wire.HandshakeDoneFrame
	MaxDataFrame            = wire.MaxDataFrame
	MaxStreamDataFrame      = wire.MaxStreamDataFrame
	MaxStreamsFrame         = wire.MaxStreamsFrame
	NewConnectionIDFrame    = wire.NewConnectionIDFrame
	NewTokenFrame           = wire.NewTokenFrame
	PathChallengeFrame      = wire.PathChallengeFrame
	PathResponseFrame       = wire.PathResponseFrame
	PingFrame               = wire.PingFrame
	ResetStreamFrame        = wire.ResetStreamFrame
	RetireConnectionIDFrame = wire.RetireConnectionIDFrame
	StopSendingFrame        = wire.StopSendingFrame
	StreamDataBlockedFrame  = wire.StreamDataBlockedFrame
	StreamFrame             = wire.StreamFrame
	StreamsBlockedFrame     = wire.StreamsBlockedFrame
)
