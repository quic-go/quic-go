package quic

import (
	"errors"
	"time"

	"github.com/lucas-clemente/quic-go/ackhandler"
	"github.com/lucas-clemente/quic-go/flowcontrol"
	"github.com/lucas-clemente/quic-go/frames"
	"github.com/lucas-clemente/quic-go/protocol"
	"github.com/lucas-clemente/quic-go/qerr"
	"github.com/lucas-clemente/quic-go/utils"
)

type sessionSender struct {
	conn connection

	sentPacketHandler     ackhandler.SentPacketHandler
	receivedPacketHandler ackhandler.ReceivedPacketHandler

	streamFramer       *streamFramer
	packer             *packetPacker
	flowControlManager flowcontrol.FlowControlManager

	nextAckScheduledTime time.Time
}

func newSessionSender(conn connection,
	sentPacketHandler ackhandler.SentPacketHandler,
	receivedPacketHandler ackhandler.ReceivedPacketHandler,
	streamFramer *streamFramer,
	packer *packetPacker,
	flowControlManager flowcontrol.FlowControlManager,
) sessionSender {
	return sessionSender{
		conn:                  conn,
		sentPacketHandler:     sentPacketHandler,
		receivedPacketHandler: receivedPacketHandler,
		streamFramer:          streamFramer,
		packer:                packer,
		flowControlManager:    flowControlManager,
	}
}

func (s *sessionSender) sendPacket() error {
	// Repeatedly try sending until we don't have any more data, or run out of the congestion window
	for {
		if !s.sentPacketHandler.SendingAllowed() {
			return nil
		}

		var controlFrames []frames.Frame

		// get WindowUpdate frames
		// this call triggers the flow controller to increase the flow control windows, if necessary
		windowUpdateFrames := s.getWindowUpdateFrames()
		for _, wuf := range windowUpdateFrames {
			controlFrames = append(controlFrames, wuf)
		}

		// check for retransmissions first
		for {
			retransmitPacket := s.sentPacketHandler.DequeuePacketForRetransmission()
			if retransmitPacket == nil {
				break
			}
			utils.Debugf("\tDequeueing retransmission for packet 0x%x", retransmitPacket.PacketNumber)

			if retransmitPacket.EncryptionLevel != protocol.EncryptionForwardSecure {
				utils.Debugf("\tDequeueing handshake retransmission for packet 0x%x", retransmitPacket.PacketNumber)
				stopWaitingFrame := s.sentPacketHandler.GetStopWaitingFrame(true)
				var packet *packedPacket
				packet, err := s.packer.RetransmitNonForwardSecurePacket(stopWaitingFrame, retransmitPacket)
				if err != nil {
					return err
				}
				if packet == nil {
					continue
				}
				err = s.sendPackedPacket(packet)
				if err != nil {
					return err
				}
				continue
			} else {
				// resend the frames that were in the packet
				for _, frame := range retransmitPacket.GetFramesForRetransmission() {
					switch frame.(type) {
					case *frames.StreamFrame:
						s.streamFramer.AddFrameForRetransmission(frame.(*frames.StreamFrame))
					case *frames.WindowUpdateFrame:
						// only retransmit WindowUpdates if the stream is not yet closed and the we haven't sent another WindowUpdate with a higher ByteOffset for the stream
						var currentOffset protocol.ByteCount
						f := frame.(*frames.WindowUpdateFrame)
						currentOffset, err := s.flowControlManager.GetReceiveWindow(f.StreamID)
						if err == nil && f.ByteOffset >= currentOffset {
							controlFrames = append(controlFrames, frame)
						}
					default:
						controlFrames = append(controlFrames, frame)
					}
				}
			}
		}

		ack := s.receivedPacketHandler.GetAckFrame()
		if ack != nil {
			controlFrames = append(controlFrames, ack)
		}
		hasRetransmission := s.streamFramer.HasFramesForRetransmission()
		var stopWaitingFrame *frames.StopWaitingFrame
		if ack != nil || hasRetransmission {
			stopWaitingFrame = s.sentPacketHandler.GetStopWaitingFrame(hasRetransmission)
		}
		packet, err := s.packer.PackPacket(stopWaitingFrame, controlFrames, s.sentPacketHandler.GetLeastUnacked())
		if err != nil {
			return err
		}
		if packet == nil {
			return nil
		}
		// send every window update twice
		for _, f := range windowUpdateFrames {
			s.packer.QueueControlFrameForNextPacket(f)
		}

		err = s.sendPackedPacket(packet)
		if err != nil {
			return err
		}
		s.nextAckScheduledTime = time.Time{}
	}
}

func (s *sessionSender) sendPackedPacket(packet *packedPacket) error {
	err := s.sentPacketHandler.SentPacket(&ackhandler.Packet{
		PacketNumber:    packet.number,
		Frames:          packet.frames,
		Length:          protocol.ByteCount(len(packet.raw)),
		EncryptionLevel: packet.encryptionLevel,
	})
	if err != nil {
		return err
	}

	s.logPacket(packet)

	err = s.conn.Write(packet.raw)
	putPacketBuffer(packet.raw)
	return err
}

func (s *sessionSender) sendConnectionClose(quicErr *qerr.QuicError) error {
	packet, err := s.packer.PackConnectionClose(&frames.ConnectionCloseFrame{ErrorCode: quicErr.ErrorCode, ReasonPhrase: quicErr.ErrorMessage}, s.sentPacketHandler.GetLeastUnacked())
	if err != nil {
		return err
	}
	if packet == nil {
		return errors.New("Session BUG: expected packet not to be nil")
	}
	s.logPacket(packet)
	return s.conn.Write(packet.raw)
}

func (s *sessionSender) logPacket(packet *packedPacket) {
	if !utils.Debug() {
		// We don't need to allocate the slices for calling the format functions
		return
	}
	if utils.Debug() {
		utils.Debugf("-> Sending packet 0x%x (%d bytes), %s", packet.number, len(packet.raw), packet.encryptionLevel)
		for _, frame := range packet.frames {
			frames.LogFrame(frame, true)
		}
	}
}

func (s *sessionSender) getWindowUpdateFrames() []*frames.WindowUpdateFrame {
	updates := s.flowControlManager.GetWindowUpdates()
	res := make([]*frames.WindowUpdateFrame, len(updates))
	for i, u := range updates {
		res[i] = &frames.WindowUpdateFrame{StreamID: u.StreamID, ByteOffset: u.Offset}
	}
	return res
}

func (s *sessionSender) getNextAckScheduledTime() time.Time {
	return s.nextAckScheduledTime
}

func (s *sessionSender) setNextAckScheduledTime(t time.Time) {
	s.nextAckScheduledTime = t
}
