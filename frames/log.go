package frames

import "github.com/lucas-clemente/quic-go/utils"

// LogFrame logs a frame, either sent or received
func LogFrame(frame Frame, sent bool) {
	if !utils.Debug() {
		return
	}
	dir := "<-"
	if sent {
		dir = "->"
	}
	if f, ok := frame.(*StreamFrame); ok {
		utils.Debugf("\t%s &frames.StreamFrame{StreamID: %d, FinBit: %t, Offset: 0x%x, Data length: 0x%x, Offset + Data length: 0x%x}", dir, f.StreamID, f.FinBit, f.Offset, f.DataLen(), f.Offset+f.DataLen())
		return
	}
	if f, ok := frame.(*StopWaitingFrame); ok {
		if sent {
			utils.Debugf("\t%s &frames.StopWaitingFrame{LeastUnacked: 0x%x, PacketNumberLen: 0x%x}", dir, f.LeastUnacked, f.PacketNumberLen)
		} else {
			utils.Debugf("\t%s &frames.StopWaitingFrame{LeastUnacked: 0x%x}", dir, f.LeastUnacked)
		}
		return
	}
	utils.Debugf("\t%s %#v", dir, frame)
}
