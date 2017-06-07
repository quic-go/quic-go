package quic

import (
	"errors"
	"fmt"
	"time"

	"github.com/lucas-clemente/quic-go/ackhandler"
	"github.com/lucas-clemente/quic-go/flowcontrol"
	"github.com/lucas-clemente/quic-go/frames"
	"github.com/lucas-clemente/quic-go/handshake"
	"github.com/lucas-clemente/quic-go/protocol"
	"github.com/lucas-clemente/quic-go/qerr"
	"github.com/lucas-clemente/quic-go/utils"
)

type sessionReceiver struct {
	perspective protocol.Perspective
	conn        connection

	sentPacketHandler     ackhandler.SentPacketHandler
	receivedPacketHandler ackhandler.ReceivedPacketHandler

	streamsMap *streamsMap

	unpacker           unpacker
	cryptoSetup        handshake.CryptoSetup
	flowControlManager flowcontrol.FlowControlManager

	closeRemote func(error)

	lastNetworkActivityTime time.Time
	largestRcvdPacketNumber protocol.PacketNumber
	// Used to calculate the next packet number from the truncated wire
	// representation, and sent back in public reset packets
	lastRcvdPacketNumber protocol.PacketNumber
}

func newSessionReceiver(perspective protocol.Perspective,
	conn connection,
	sentPacketHandler ackhandler.SentPacketHandler,
	receivedPacketHandler ackhandler.ReceivedPacketHandler,
	streamsMap *streamsMap,
	streamFramer *streamFramer,
	unpacker unpacker,
	cryptoSetup handshake.CryptoSetup,
	flowControlManager flowcontrol.FlowControlManager,
	closeRemote func(error),
) sessionReceiver {
	return sessionReceiver{
		perspective:             perspective,
		conn:                    conn,
		sentPacketHandler:       sentPacketHandler,
		receivedPacketHandler:   receivedPacketHandler,
		streamsMap:              streamsMap,
		unpacker:                unpacker,
		cryptoSetup:             cryptoSetup,
		flowControlManager:      flowControlManager,
		lastNetworkActivityTime: time.Now(),
		closeRemote:             closeRemote,
	}
}

func (s *sessionReceiver) handlePacketImpl(p *receivedPacket) error {
	if s.perspective == protocol.PerspectiveClient {
		diversificationNonce := p.publicHeader.DiversificationNonce
		if len(diversificationNonce) > 0 {
			s.cryptoSetup.SetDiversificationNonce(diversificationNonce)
		}
	}

	if p.rcvTime.IsZero() {
		// To simplify testing
		p.rcvTime = time.Now()
	}

	s.lastNetworkActivityTime = p.rcvTime
	hdr := p.publicHeader
	data := p.data

	// Calculate packet number
	hdr.PacketNumber = protocol.InferPacketNumber(
		hdr.PacketNumberLen,
		s.largestRcvdPacketNumber,
		hdr.PacketNumber,
	)

	packet, err := s.unpacker.Unpack(hdr.Raw, hdr, data)
	if utils.Debug() {
		if err != nil {
			utils.Debugf("<- Reading packet 0x%x (%d bytes) for connection %x", hdr.PacketNumber, len(data)+len(hdr.Raw), hdr.ConnectionID)
		} else {
			utils.Debugf("<- Reading packet 0x%x (%d bytes) for connection %x, %s", hdr.PacketNumber, len(data)+len(hdr.Raw), hdr.ConnectionID, packet.encryptionLevel)
		}
	}
	// if the decryption failed, this might be a packet sent by an attacker
	// don't update the remote address
	if quicErr, ok := err.(*qerr.QuicError); ok && quicErr.ErrorCode == qerr.DecryptionFailure {
		return err
	}
	if s.perspective == protocol.PerspectiveServer {
		// update the remote address, even if unpacking failed for any other reason than a decryption error
		s.conn.SetCurrentRemoteAddr(p.remoteAddr)
	}
	if err != nil {
		return err
	}

	s.lastRcvdPacketNumber = hdr.PacketNumber
	// Only do this after decrypting, so we are sure the packet is not attacker-controlled
	s.largestRcvdPacketNumber = utils.MaxPacketNumber(s.largestRcvdPacketNumber, hdr.PacketNumber)

	err = s.receivedPacketHandler.ReceivedPacket(hdr.PacketNumber, packet.IsRetransmittable())
	// ignore duplicate packets
	if err == ackhandler.ErrDuplicatePacket {
		utils.Infof("Ignoring packet 0x%x due to ErrDuplicatePacket", hdr.PacketNumber)
		return nil
	}
	// ignore packets with packet numbers smaller than the LeastUnacked of a StopWaiting
	if err == ackhandler.ErrPacketSmallerThanLastStopWaiting {
		utils.Infof("Ignoring packet 0x%x due to ErrPacketSmallerThanLastStopWaiting", hdr.PacketNumber)
		return nil
	}

	if err != nil {
		return err
	}

	return s.handleFrames(packet.frames)
}

func (s *sessionReceiver) handleFrames(fs []frames.Frame) error {
	for _, ff := range fs {
		var err error
		frames.LogFrame(ff, false)
		switch frame := ff.(type) {
		case *frames.StreamFrame:
			err = s.handleStreamFrame(frame)
		case *frames.AckFrame:
			err = s.handleAckFrame(frame)
		case *frames.ConnectionCloseFrame:
			s.closeRemote(qerr.Error(frame.ErrorCode, frame.ReasonPhrase))
		case *frames.GoawayFrame:
			err = errors.New("unimplemented: handling GOAWAY frames")
		case *frames.StopWaitingFrame:
			err = s.receivedPacketHandler.ReceivedStopWaiting(frame)
		case *frames.RstStreamFrame:
			err = s.handleRstStreamFrame(frame)
		case *frames.WindowUpdateFrame:
			err = s.handleWindowUpdateFrame(frame)
		case *frames.BlockedFrame:
		case *frames.PingFrame:
		default:
			return errors.New("Session BUG: unexpected frame type")
		}

		if err != nil {
			switch err {
			case ackhandler.ErrDuplicateOrOutOfOrderAck:
				// Can happen e.g. when packets thought missing arrive late
			case errRstStreamOnInvalidStream:
				// Can happen when RST_STREAMs arrive early or late (?)
				utils.Errorf("Ignoring error in session: %s", err.Error())
			case errWindowUpdateOnClosedStream:
				// Can happen when we already sent the last StreamFrame with the FinBit, but the client already sent a WindowUpdate for this Stream
			default:
				return err
			}
		}
	}
	return nil
}

func (s *sessionReceiver) handleStreamFrame(frame *frames.StreamFrame) error {
	str, err := s.streamsMap.GetOrOpenStream(frame.StreamID)
	if err != nil {
		return err
	}
	if str == nil {
		// Stream is closed and already garbage collected
		// ignore this StreamFrame
		return nil
	}
	return str.AddStreamFrame(frame)
}

func (s *sessionReceiver) handleWindowUpdateFrame(frame *frames.WindowUpdateFrame) error {
	if frame.StreamID != 0 {
		str, err := s.streamsMap.GetOrOpenStream(frame.StreamID)
		if err != nil {
			return err
		}
		if str == nil {
			return errWindowUpdateOnClosedStream
		}
	}
	_, err := s.flowControlManager.UpdateWindow(frame.StreamID, frame.ByteOffset)
	return err
}

func (s *sessionReceiver) handleRstStreamFrame(frame *frames.RstStreamFrame) error {
	str, err := s.streamsMap.GetOrOpenStream(frame.StreamID)
	if err != nil {
		return err
	}
	if str == nil {
		return errRstStreamOnInvalidStream
	}

	str.RegisterRemoteError(fmt.Errorf("RST_STREAM received with code %d", frame.ErrorCode))
	return s.flowControlManager.ResetStream(frame.StreamID, frame.ByteOffset)
}

func (s *sessionReceiver) handleAckFrame(frame *frames.AckFrame) error {
	return s.sentPacketHandler.ReceivedAck(frame, s.lastRcvdPacketNumber, s.lastNetworkActivityTime)
}

func (s *sessionReceiver) getLastRcvdPacketNumber() protocol.PacketNumber {
	return s.lastRcvdPacketNumber
}

func (s *sessionReceiver) getLastNetworkActivityTime() time.Time {
	return s.lastNetworkActivityTime
}
