package congestion

import (
	"fmt"
	"time"

	"github.com/lucas-clemente/quic-go/internal/utils"
	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/wire"
)

// static
func IsAckable(state protocol.SentPacketState) bool {
	return state != protocol.NEVER_SENT && state != protocol.ACKED && state != protocol.UNACKABLE;
}

// Class which tracks unacked packets for three purposes:
// 1) Track retransmittable data, including multiple transmissions of frames.
// 2) Track packets and bytes in flight for congestion control.
// 3) Track sent time of packets to provide RTT measurements from acks.
type UnackedPacketMap struct {

	largest_sent_packet_ 									protocol.PacketNumber
	// The largest sent packet we expect to receive an ack for.
	largest_sent_retransmittable_packet_ protocol.PacketNumber
	// The largest sent largestAcked in an ACK frame.
	largest_sent_largest_acked_ protocol.PacketNumber
	// The largest received largestAcked from an ACK frame.
	largest_acked_ protocol.PacketNumber

	// Newly serialized retransmittable packets are added to this map, which
	// contains owning pointers to any contained frames.  If a packet is
	// retransmitted, this map will contain entries for both the old and the new
	// packet. The old packet's retransmittable frames entry will be nullptr,
	// while the new packet's entry will contain the frames to retransmit.
	// If the old packet is acked before the new packet, then the old entry will
	// be removed from the map and the new entry's retransmittable frames will be
	// set to nullptr.
	unacked_packets_ []TransmissionInfo
	// The packet at the 0th index of unacked_packets_.
	least_unacked_ protocol.PacketNumber

	bytesInFlight protocol.ByteCount;
	// Number of retransmittable crypto handshake packets.
	pending_crypto_packet_count_ int

	// Time that the last unacked crypto packet was sent.
	last_crypto_packet_sent_time_ time.Time

	// Aggregates acked stream data across multiple acked sent packets to save CPU
	// by reducing the number of calls to the session notifier.
	aggregated_stream_frame_ wire.StreamFrame

	//// Receives notifications of frames being retransmitted or acknowledged.
	//session_notifier_ *SessionNotifierInterface

	// If true, let session decides what to write.
	session_decides_what_to_write_ bool
}

func (p *UnackedPacketMap) BytesInFlight() protocol.ByteCount {
	return p.bytesInFlight
}

// Adds |serialized_packet| to the map and marks it as sent at |sent_time|.
// Marks the packet as in flight if |set_in_flight| is true.
// Packets marked as in flight are expected to be marked as missing when they
// don't arrive, indicating the need for retransmission.
// |old_packet_number| is the packet number of the previous transmission,
// or 0 if there was none.
// Any AckNotifierWrappers in |serialized_packet| are swapped from the
// serialized packet into the QuicTransmissionInfo.
func(p *UnackedPacketMap) AddSentPacket(packet *SerializedPacket,
	oldPacketNumber protocol.PacketNumber,
	transmissionType protocol.TransmissionType,
	sentTime time.Time,
	setInFlight bool) {
	packetNumber := packet.packetNumber;
	bytesSent := packet.encryptedLength;
	if p.largest_sent_packet_ != 0 && p.largest_sent_packet_ >= packetNumber {
		fmt.Println("largest_sent_packet_: %d, packetNumber: ", p.largest_sent_packet_, packetNumber)
	}
	//DCHECK_GE(packetNumber >= p.least_unacked_ + protocol.PacketNumber(len(p.unacked_packets_)))
	for ;p.least_unacked_ + protocol.PacketNumber(len(p.unacked_packets_)) < packetNumber; {
		p.unacked_packets_ = append(p.unacked_packets_,*DefaultNewTransmissionInfo())
		p.unacked_packets_[len(p.unacked_packets_)-1].State() = protocol.NEVER_SENT
	}

	has_crypto_handshake := packet.hasCryptoHandshake == true;
	info := *NewTransmissionInfo(
		packet.encryptionLevel,
		packet.packetNumberLength,
		transmissionType,
		sentTime,
		bytesSent,
		has_crypto_handshake,
		int(packet.numPaddingBytes))

	info.SetLargestAcked(packet.largestAcked)
	if packet.largestAcked != 0 {
		if p.largest_sent_largest_acked_ != 0 {
			p.largest_sent_largest_acked_ = utils.MaxPacketNumber(p.largest_sent_largest_acked_, packet.largestAcked)
		} else {
			p.largest_sent_largest_acked_ = packet.largestAcked
		}
	}
	if oldPacketNumber != 0 {
	p.TransferRetransmissionInfo(oldPacketNumber, packetNumber,
		transmissionType, &info);
	}

	p.largest_sent_packet_ = packetNumber;
	if setInFlight {
		p.bytesInFlight += protocol.ByteCount(bytesSent)
		info.SetInFlight(true)
		p.largest_sent_retransmittable_packet_ = packetNumber
	}
	p.unacked_packets_=append(p.unacked_packets_, info);
	// Swap the retransmittable frames to avoid allocations.
	// TODO(ianswett): Could use emplace_back when Chromium can.
	if oldPacketNumber == 0 {
		if has_crypto_handshake {
			p.pending_crypto_packet_count_+=1;
			p.last_crypto_packet_sent_time_ = sentTime;
		}

		packet.retransmittableFrames, p.unacked_packets_[len(p.unacked_packets_)-1].retransmittableFrames =
		p.unacked_packets_[len(p.unacked_packets_)-1].retransmittableFrames, packet.retransmittableFrames
	}
}

func(p *UnackedPacketMap) TransferRetransmissionInfo (
	oldPacketNumber protocol.PacketNumber,
	newPacketNumber protocol.PacketNumber,
 	transmissionType protocol.TransmissionType,
	info * TransmissionInfo) {
	if (oldPacketNumber < p.least_unacked_) {
		// This can happen when a retransmission packet is queued because of write
		// blocked socket, and the original packet gets acked before the
		// retransmission gets sent.
		return
	}
	if (oldPacketNumber > p.largest_sent_packet_) {
		fmt.Println("Old QuicTransmissionInfo never existed for :%d largest_sent:%d",
			oldPacketNumber,
			p.largest_sent_packet_)
		return
	}
	//DCHECK_GE(newPacketNumber, least_unacked_ + unacked_packets_.size());
	//DCHECK_NE(NOT_RETRANSMISSION, transmissionType);

	transmission_info := &p.unacked_packets_[oldPacketNumber- p.least_unacked_]
	frames := transmission_info.retransmittableFrames;
	//if session_notifier_ != nil {
	//	for _, frame :range frames {
	//		if (frame.type == STREAM_FRAME) {
	//			session_notifier_->OnStreamFrameRetransmitted(frame.stream_frame);
	//		}
	//	}
	//}

	// Swap the frames and preserve numPaddingBytes and hasCryptoHandshake.
	frames, info.retransmittableFrames = info.retransmittableFrames, frames
	info.hasCryptoHandshake = transmission_info.hasCryptoHandshake
	transmission_info.hasCryptoHandshake = false
	info.numPaddingBytes = transmission_info.numPaddingBytes

	// Don't link old transmissions to new ones when version or
	// encryption changes.
	if transmissionType == protocol.ALL_INITIAL_RETRANSMISSION ||
	transmissionType == protocol.ALL_UNACKED_RETRANSMISSION {
		transmission_info.SetState(protocol.UNACKABLE)
	} else {
		transmission_info.retransmission = newPacketNumber;
	}
	// Proactively remove obsolete packets so the least unacked can be raised.
	p.RemoveObsoletePackets();
}


// Returns true if the packet |packetNumber| is unacked.
func(p *UnackedPacketMap) IsUnacked(packetNumber protocol.PacketNumber) bool {
	if packetNumber < p.least_unacked_ ||
		packetNumber >= p.least_unacked_ + protocol.PacketNumber(len(p.unacked_packets_)) {
		return false
	}
	return !p.IsPacketUseless(packetNumber,
	&p.unacked_packets_[packetNumber- p.least_unacked_])
}


// Returns true if |info| has retransmittable frames. This will return false
// if all frames of this packet are either non-retransmittable or have been
// acked.
func(p *UnackedPacketMap) HasRetransmittableFrames(info *TransmissionInfo) bool {
	if !p.session_decides_what_to_write_ {
		return len(info.retransmittableFrames) > 0
	}
	if !IsAckable(info.state) {
		return false
	}

	//for _, frame := range info.retransmittableFrames {
	//	if (p.session_notifier_.IsFrameOutstanding(frame)) {
	//		return true
	//	}
	//}
	return false
}



// Returns the smallest packet number of a serialized packet which has not
// been acked by the peer.  If there are no unacked packets, returns 0.
func(p *UnackedPacketMap) GetLeastUnacked() protocol.PacketNumber {
	return p.least_unacked_
}

// Remove any packets no longer needed for retransmission, congestion, or
// RTT measurement purposes.
func(p *UnackedPacketMap) RemoveObsoletePackets() {
	for ;len(p.unacked_packets_)>0; {
		if !p.IsPacketUseless(p.least_unacked_, &p.unacked_packets_[0]) {
			break
		}
		if p.session_decides_what_to_write_ {
			//DeleteFrames(&p.unacked_packets_[0].retransmittableFrames);
		}
		p.unacked_packets_ = p.unacked_packets_[1:]
		p.least_unacked_+=1
	}
}

// Returns true if packet may be useful for an RTT measurement.
func(p *UnackedPacketMap) IsPacketUsefulForMeasuringRtt(packet_number protocol.PacketNumber,
info *TransmissionInfo) bool {
	// Packet can be used for RTT measurement if it may yet be acked as the
	// largest observed packet by the receiver.
	return IsAckable(info.state) &&
	(p.largest_acked_ == 0 || packet_number > p.largest_acked_);
}

// Returns true if packet may be useful for congestion control purposes.
func(p *UnackedPacketMap) IsPacketUsefulForCongestionControl(
	info *TransmissionInfo) bool {
	// Packet contributes to congestion control if it is considered inflight.
	return info.inFlight;
}

// Returns true if packet may be associated with retransmittable data
// directly or through retransmissions.
func(p *UnackedPacketMap) IsPacketUsefulForRetransmittableData(
	info *TransmissionInfo) bool {
	if (!p.session_decides_what_to_write_) {
		// Packet may have retransmittable frames, or the data may have been
		// retransmitted with a new packet number.
		// Allow for an extra 1 RTT before stopping to track old packets.
		return info.retransmission != 0 &&
		(p.largest_acked_ == 0 ||
		info.retransmission > p.largest_acked_) ||
		p.HasRetransmittableFrames(info)
	}

	// Wait for 1 RTT before giving up on the lost packet.
	return info.retransmission != 0 &&
	(p.largest_acked_ == 0 ||
	info.retransmission > p.largest_acked_);
}

// Returns true if the packet no longer has a purpose in the map.
func(p *UnackedPacketMap) IsPacketUseless(packet_number protocol.PacketNumber,
	info *TransmissionInfo) bool {
	return !p.IsPacketUsefulForMeasuringRtt(packet_number, info) &&
	!p.IsPacketUsefulForCongestionControl(info) &&
	!p.IsPacketUsefulForRetransmittableData(info)
}







