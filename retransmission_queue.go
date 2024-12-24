package quic

import (
	"fmt"

	"github.com/quic-go/quic-go/internal/ackhandler"

	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/wire"
)

type retransmissionQueue struct {
	initial           []wire.Frame
	initialCryptoData []*wire.CryptoFrame

	handshake           []wire.Frame
	handshakeCryptoData []*wire.CryptoFrame

	appData []wire.Frame
}

func newRetransmissionQueue() *retransmissionQueue {
	return &retransmissionQueue{}
}

func (q *retransmissionQueue) addInitial(f wire.Frame) {
	if cf, ok := f.(*wire.CryptoFrame); ok {
		q.initialCryptoData = append(q.initialCryptoData, cf)
		return
	}
	q.initial = append(q.initial, f)
}

func (q *retransmissionQueue) addHandshake(f wire.Frame) {
	if cf, ok := f.(*wire.CryptoFrame); ok {
		q.handshakeCryptoData = append(q.handshakeCryptoData, cf)
		return
	}
	q.handshake = append(q.handshake, f)
}

func (q *retransmissionQueue) HasData(encLevel protocol.EncryptionLevel) bool {
	//nolint:exhaustive // 0-RTT data is retransmitted in 1-RTT packets.
	switch encLevel {
	case protocol.EncryptionInitial:
		return len(q.initialCryptoData) > 0 || len(q.initial) > 0
	case protocol.EncryptionHandshake:
		return len(q.handshakeCryptoData) > 0 || len(q.handshake) > 0
	case protocol.Encryption1RTT:
		return len(q.appData) > 0
	}
	return false
}

func (q *retransmissionQueue) addAppData(f wire.Frame) {
	if _, ok := f.(*wire.StreamFrame); ok {
		panic("STREAM frames are handled with their respective streams.")
	}
	q.appData = append(q.appData, f)
}

func (q *retransmissionQueue) GetFrame(encLevel protocol.EncryptionLevel, maxLen protocol.ByteCount, v protocol.Version) wire.Frame {
	//nolint:exhaustive // 0-RTT packets can't contain retransmissions
	switch encLevel {
	case protocol.EncryptionInitial:
		return q.getInitialFrame(maxLen, v)
	case protocol.EncryptionHandshake:
		return q.getHandshakeFrame(maxLen, v)
	case protocol.Encryption1RTT:
		return q.getAppDataFrame(maxLen, v)
	}
	return nil
}

func (q *retransmissionQueue) getInitialFrame(maxLen protocol.ByteCount, v protocol.Version) wire.Frame {
	if len(q.initialCryptoData) > 0 {
		f := q.initialCryptoData[0]
		newFrame, needsSplit := f.MaybeSplitOffFrame(maxLen, v)
		if newFrame == nil && !needsSplit { // the whole frame fits
			q.initialCryptoData = q.initialCryptoData[1:]
			return f
		}
		if newFrame != nil { // frame was split. Leave the original frame in the queue.
			return newFrame
		}
	}
	if len(q.initial) == 0 {
		return nil
	}
	f := q.initial[0]
	if f.Length(v) > maxLen {
		return nil
	}
	q.initial = q.initial[1:]
	return f
}

func (q *retransmissionQueue) getHandshakeFrame(maxLen protocol.ByteCount, v protocol.Version) wire.Frame {
	if len(q.handshakeCryptoData) > 0 {
		f := q.handshakeCryptoData[0]
		newFrame, needsSplit := f.MaybeSplitOffFrame(maxLen, v)
		if newFrame == nil && !needsSplit { // the whole frame fits
			q.handshakeCryptoData = q.handshakeCryptoData[1:]
			return f
		}
		if newFrame != nil { // frame was split. Leave the original frame in the queue.
			return newFrame
		}
	}
	if len(q.handshake) == 0 {
		return nil
	}
	f := q.handshake[0]
	if f.Length(v) > maxLen {
		return nil
	}
	q.handshake = q.handshake[1:]
	return f
}

func (q *retransmissionQueue) getAppDataFrame(maxLen protocol.ByteCount, v protocol.Version) wire.Frame {
	if len(q.appData) == 0 {
		return nil
	}
	f := q.appData[0]
	if f.Length(v) > maxLen {
		return nil
	}
	q.appData = q.appData[1:]
	return f
}

func (q *retransmissionQueue) DropPackets(encLevel protocol.EncryptionLevel) {
	//nolint:exhaustive // Can only drop Initial and Handshake packet number space.
	switch encLevel {
	case protocol.EncryptionInitial:
		q.initial = nil
		q.initialCryptoData = nil
	case protocol.EncryptionHandshake:
		q.handshake = nil
		q.handshakeCryptoData = nil
	default:
		panic(fmt.Sprintf("unexpected encryption level: %s", encLevel))
	}
}

func (q *retransmissionQueue) AckHandler(encLevel protocol.EncryptionLevel) ackhandler.FrameHandler {
	switch encLevel {
	case protocol.EncryptionInitial:
		return (*retransmissionQueueInitialAckHandler)(q)
	case protocol.EncryptionHandshake:
		return (*retransmissionQueueHandshakeAckHandler)(q)
	case protocol.Encryption0RTT, protocol.Encryption1RTT:
		return (*retransmissionQueueAppDataAckHandler)(q)
	}
	return nil
}

type retransmissionQueueInitialAckHandler retransmissionQueue

func (q *retransmissionQueueInitialAckHandler) OnAcked(wire.Frame) {}
func (q *retransmissionQueueInitialAckHandler) OnLost(f wire.Frame) {
	(*retransmissionQueue)(q).addInitial(f)
}

type retransmissionQueueHandshakeAckHandler retransmissionQueue

func (q *retransmissionQueueHandshakeAckHandler) OnAcked(wire.Frame) {}
func (q *retransmissionQueueHandshakeAckHandler) OnLost(f wire.Frame) {
	(*retransmissionQueue)(q).addHandshake(f)
}

type retransmissionQueueAppDataAckHandler retransmissionQueue

func (q *retransmissionQueueAppDataAckHandler) OnAcked(wire.Frame) {}
func (q *retransmissionQueueAppDataAckHandler) OnLost(f wire.Frame) {
	(*retransmissionQueue)(q).addAppData(f)
}
