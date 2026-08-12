package quic

import (
	"bytes"
	"encoding/binary"
	"math/rand/v2"
	"testing"

	"github.com/quic-go/quic-go/internal/ackhandler"
	"github.com/quic-go/quic-go/internal/monotime"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/wire"

	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

func TestFramerControlFrames(t *testing.T) {
	pc := &wire.PathChallengeFrame{Data: [8]byte{1, 2, 3, 4, 6, 7, 8}}
	msf := &wire.MaxStreamsFrame{MaxStreamNum: 0x1337}

	framer := newFramer(newConnectionFlowController(0, 0, nil, nil, nil))
	require.False(t, framer.HasData())
	framer.QueueControlFrame(pc)
	require.True(t, framer.HasData())
	framer.QueueControlFrame(msf)
	frames, streamFrames, length := framer.Append(
		[]ackhandler.Frame{{Frame: &wire.PingFrame{}}},
		nil,
		protocol.MaxByteCount,
		monotime.Now(),
		protocol.Version1,
	)
	require.Len(t, frames, 3)
	require.Empty(t, streamFrames)
	require.Contains(t, frames, ackhandler.Frame{Frame: &wire.PingFrame{}})
	require.Contains(t, frames, ackhandler.Frame{Frame: pc})
	require.Contains(t, frames, ackhandler.Frame{Frame: msf})
	require.Equal(t, length, pc.Length(protocol.Version1)+msf.Length(protocol.Version1))
	require.False(t, framer.HasData())
}

func TestFramerControlFrameSizing(t *testing.T) {
	const maxSize = protocol.ByteCount(1000)
	bf := &wire.DataBlockedFrame{MaximumData: 0x1337}
	bfLen := bf.Length(protocol.Version1)

	framer := newFramer(newConnectionFlowController(0, 0, nil, nil, nil))
	numFrames := int(maxSize / bfLen) // max number of frames that fit into maxSize
	for i := 0; i < numFrames+1; i++ {
		framer.QueueControlFrame(bf)
	}
	frames, _, length := framer.Append(nil, nil, maxSize, monotime.Now(), protocol.Version1)
	require.Len(t, frames, numFrames)
	require.Greater(t, length, maxSize-bfLen)
	// now make sure that the last frame is also added
	frames, _, length = framer.Append(nil, nil, maxSize, monotime.Now(), protocol.Version1)
	require.Len(t, frames, 1)
	require.Equal(t, length, bfLen)
}

func TestFramerStreamControlFrames(t *testing.T) {
	const streamID = protocol.StreamID(10)
	ping := &wire.PingFrame{}
	mdf1 := &wire.MaxStreamDataFrame{StreamID: streamID, MaximumStreamData: 1337}
	mdf2 := &wire.MaxStreamDataFrame{StreamID: streamID, MaximumStreamData: 1338}

	framer := newFramer(newConnectionFlowController(0, 0, nil, nil, nil))
	framer.QueueControlFrame(ping)
	str := NewMockStreamControlFrameGetter(gomock.NewController(t))
	framer.AddStreamWithControlFrames(streamID, str)
	now := monotime.Now()
	str.EXPECT().getControlFrame(now).Return(ackhandler.Frame{Frame: mdf1}, true, true)
	str.EXPECT().getControlFrame(now).Return(ackhandler.Frame{Frame: mdf2}, true, false)
	frames, streamFrames, l := framer.Append(nil, nil, protocol.MaxByteCount, now, protocol.Version1)
	require.Len(t, frames, 3)
	require.Empty(t, streamFrames)
	require.Equal(t, mdf1, frames[0].Frame)
	require.Equal(t, mdf2, frames[1].Frame)
	require.Equal(t, ping, frames[2].Frame)
	require.Equal(t, ping.Length(protocol.Version1)+mdf1.Length(protocol.Version1)+mdf2.Length(protocol.Version1), l)
}

// If there are less than 25 bytes left, no more stream-related control frames are enqueued.
// This avoids dequeueing a frame from the stream that would be too large to fit into the packet.
func TestFramerStreamControlFramesSizing(t *testing.T) {
	mdf1 := &wire.MaxStreamDataFrame{MaximumStreamData: 1337}

	str := NewMockStreamControlFrameGetter(gomock.NewController(t))
	framer := newFramer(newConnectionFlowController(0, 0, nil, nil, nil))
	framer.AddStreamWithControlFrames(10, str)
	str.EXPECT().getControlFrame(gomock.Any()).Return(ackhandler.Frame{Frame: mdf1}, true, true).AnyTimes()
	frames, _, l := framer.Append(nil, nil, 100, monotime.Now(), protocol.Version1)
	require.Equal(t, protocol.ByteCount(len(frames))*mdf1.Length(protocol.Version1), l)
	require.Greater(t, l, protocol.ByteCount(100-maxStreamControlFrameSize))
	require.LessOrEqual(t, l, protocol.ByteCount(100))
}

func TestFramerStreamDataBlocked(t *testing.T) {
	t.Run("small STREAM frame", func(t *testing.T) {
		testFramerStreamDataBlocked(t, true)
	})

	t.Run("large STREAM frame", func(t *testing.T) {
		testFramerStreamDataBlocked(t, false)
	})
}

// If the stream becomes blocked on stream flow control, we attempt to pack the STREAM_DATA_BLOCKED
// into the same packet.
// However, there's the pathological case, where the STREAM frame and the STREAM_DATA_BLOCKED frame
// don't fit into the same packet. In that case, the STREAM_DATA_BLOCKED frame is queued and sent
// in the next packet.
func testFramerStreamDataBlocked(t *testing.T, fits bool) {
	const streamID = 5
	str := NewMockStreamFrameGetter(gomock.NewController(t))
	str.EXPECT().priority().Return(defaultUrgency, true, uint32(0)).AnyTimes()
	framer := newFramer(newConnectionFlowController(0, 0, nil, nil, nil))
	framer.AddActiveStream(streamID, str)
	str.EXPECT().popStreamFrame(gomock.Any(), gomock.Any()).DoAndReturn(
		func(size protocol.ByteCount, v protocol.Version) (ackhandler.StreamFrame, *wire.StreamDataBlockedFrame, bool) {
			data := []byte("foobar")
			if !fits {
				// Leave 3 bytes in the packet.
				// This is not enough to fit in the STREAM_DATA_BLOCKED frame.
				data = make([]byte, size-3)
			}
			f := &wire.StreamFrame{StreamID: streamID, DataLenPresent: true, Data: data}
			blocked := &wire.StreamDataBlockedFrame{StreamID: streamID, MaximumStreamData: f.DataLen()}
			if !fits {
				require.Greater(t, blocked.Length(protocol.Version1), protocol.ByteCount(3))
			}
			return ackhandler.StreamFrame{Frame: f}, blocked, false
		},
	)

	const maxSize protocol.ByteCount = 1000
	frames, streamFrames, l := framer.Append(nil, nil, maxSize, monotime.Now(), protocol.Version1)
	require.Len(t, streamFrames, 1)
	dataLen := streamFrames[0].Frame.DataLen()
	if fits {
		require.Len(t, frames, 1)
		require.Equal(t, &wire.StreamDataBlockedFrame{StreamID: streamID, MaximumStreamData: dataLen}, frames[0].Frame)
	} else {
		require.Equal(t, streamFrames[0].Frame.Length(protocol.Version1), l)
		require.Empty(t, frames)
		frames, streamFrames, l2 := framer.Append(nil, nil, maxSize, monotime.Now(), protocol.Version1)
		require.Greater(t, l+l2, maxSize)
		require.Empty(t, streamFrames)
		require.Len(t, frames, 1)
		require.Equal(t, &wire.StreamDataBlockedFrame{StreamID: streamID, MaximumStreamData: dataLen}, frames[0].Frame)
	}
}

func TestFramerDataBlocked(t *testing.T) {
	t.Run("small STREAM frame", func(t *testing.T) {
		testFramerDataBlocked(t, true)
	})

	t.Run("large STREAM frame", func(t *testing.T) {
		testFramerDataBlocked(t, false)
	})
}

// If the stream becomes blocked on connection flow control, we attempt to pack the
// DATA_BLOCKED frame into the same packet.
// However, there's the pathological case, where the STREAM frame and the DATA_BLOCKED frame
// don't fit into the same packet. In that case, the DATA_BLOCKED frame is queued and sent
// in the next packet.
func testFramerDataBlocked(t *testing.T, fits bool) {
	const streamID = 5
	const offset = 100

	fc := newConnectionFlowController(0, 0, nil, nil, nil)
	fc.UpdateSendWindow(offset)
	require.True(t, fc.TryAddBytesSent(offset))

	str := NewMockStreamFrameGetter(gomock.NewController(t))
	str.EXPECT().priority().Return(defaultUrgency, true, uint32(0)).AnyTimes()
	framer := newFramer(fc)
	framer.AddActiveStream(streamID, str)

	str.EXPECT().popStreamFrame(gomock.Any(), gomock.Any()).DoAndReturn(
		func(size protocol.ByteCount, v protocol.Version) (ackhandler.StreamFrame, *wire.StreamDataBlockedFrame, bool) {
			data := []byte("foobar")
			if !fits {
				// Leave 2 bytes in the packet.
				// This is not enough to fit in the DATA_BLOCKED frame.
				data = make([]byte, size-2)
			}
			f := &wire.StreamFrame{StreamID: streamID, DataLenPresent: true, Data: data}
			return ackhandler.StreamFrame{Frame: f}, nil, false
		},
	)

	const maxSize protocol.ByteCount = 1000
	frames, streamFrames, l := framer.Append(nil, nil, maxSize, monotime.Now(), protocol.Version1)
	require.Len(t, streamFrames, 1)
	if fits {
		require.Len(t, frames, 1)
		require.Equal(t, &wire.DataBlockedFrame{MaximumData: offset}, frames[0].Frame)
	} else {
		require.Equal(t, streamFrames[0].Frame.Length(protocol.Version1), l)
		require.Empty(t, frames)
		frames, streamFrames, l2 := framer.Append(nil, nil, maxSize, monotime.Now(), protocol.Version1)
		require.Greater(t, l+l2, maxSize)
		require.Empty(t, streamFrames)
		require.Len(t, frames, 1)
		require.Equal(t, &wire.DataBlockedFrame{MaximumData: offset}, frames[0].Frame)
	}
}

func TestFramerDetectsFrameDoS(t *testing.T) {
	framer := newFramer(newConnectionFlowController(0, 0, nil, nil, nil))
	for i := range maxControlFrames - 1 {
		framer.QueueControlFrame(&wire.PingFrame{})
		framer.QueueControlFrame(&wire.PingFrame{})
		require.False(t, framer.QueuedTooManyControlFrames())
		frames, _, _ := framer.Append([]ackhandler.Frame{}, nil, 1, monotime.Now(), protocol.Version1)
		require.Len(t, frames, 1)
		require.Len(t, framer.controlFrames, i+1)
	}
	framer.QueueControlFrame(&wire.PingFrame{})
	require.False(t, framer.QueuedTooManyControlFrames())
	require.Len(t, framer.controlFrames, maxControlFrames)
	framer.QueueControlFrame(&wire.PingFrame{})
	require.True(t, framer.QueuedTooManyControlFrames())
	require.Len(t, framer.controlFrames, maxControlFrames)
}

func TestFramerDetectsFramePathResponseDoS(t *testing.T) {
	framer := newFramer(newConnectionFlowController(0, 0, nil, nil, nil))
	var pathResponses []*wire.PathResponseFrame
	for range 2 * maxPathResponses {
		var f wire.PathResponseFrame
		binary.BigEndian.PutUint64(f.Data[:], rand.Uint64())
		pathResponses = append(pathResponses, &f)
		framer.QueueControlFrame(&f)
	}
	for i := range maxPathResponses {
		require.True(t, framer.HasData())
		frames, _, length := framer.Append(nil, nil, protocol.MaxByteCount, monotime.Now(), protocol.Version1)
		require.Len(t, frames, 1)
		require.Equal(t, pathResponses[i], frames[0].Frame)
		require.Equal(t, pathResponses[i].Length(protocol.Version1), length)
	}
	require.False(t, framer.HasData())
	frames, _, length := framer.Append(nil, nil, protocol.MaxByteCount, monotime.Now(), protocol.Version1)
	require.Empty(t, frames)
	require.Zero(t, length)
}

func TestFramerPacksSinglePathResponsePerPacket(t *testing.T) {
	framer := newFramer(newConnectionFlowController(0, 0, nil, nil, nil))
	f1 := &wire.PathResponseFrame{Data: [8]byte{1, 2, 3, 4, 5, 6, 7, 8}}
	f2 := &wire.PathResponseFrame{Data: [8]byte{2, 3, 4, 5, 6, 7, 8, 9}}
	cf1 := &wire.DataBlockedFrame{MaximumData: 1337}
	cf2 := &wire.HandshakeDoneFrame{}
	framer.QueueControlFrame(f1)
	framer.QueueControlFrame(f2)
	framer.QueueControlFrame(cf1)
	framer.QueueControlFrame(cf2)
	// the first packet should contain a single PATH_RESPONSE frame, but all the other control frames
	frames, _, _ := framer.Append(nil, nil, protocol.MaxByteCount, monotime.Now(), protocol.Version1)
	require.Len(t, frames, 3)
	require.Equal(t, f1, frames[0].Frame)
	require.Contains(t, []wire.Frame{frames[1].Frame, frames[2].Frame}, cf1)
	require.Contains(t, []wire.Frame{frames[1].Frame, frames[2].Frame}, cf2)
	// the second packet should contain the other PATH_RESPONSE frame
	require.True(t, framer.HasData())
	frames, _, _ = framer.Append(nil, nil, protocol.MaxByteCount, monotime.Now(), protocol.Version1)
	require.Len(t, frames, 1)
	require.Equal(t, f2, frames[0].Frame)
	require.False(t, framer.HasData())
}

func TestFramerAppendStreamFrames(t *testing.T) {
	const (
		str1ID = protocol.StreamID(42)
		str2ID = protocol.StreamID(43)
	)
	f1 := &wire.StreamFrame{StreamID: str1ID, Data: []byte("foo"), DataLenPresent: true}
	f2 := &wire.StreamFrame{StreamID: str2ID, Data: []byte("bar"), DataLenPresent: true}
	totalLen := f1.Length(protocol.Version1) + f2.Length(protocol.Version1)

	framer := newFramer(newConnectionFlowController(0, 0, nil, nil, nil))
	require.False(t, framer.HasData())
	// no frames added yet
	controlFrames, fs, length := framer.Append(nil, nil, protocol.MaxByteCount, monotime.Now(), protocol.Version1)
	require.Empty(t, controlFrames)
	require.Empty(t, fs)
	require.Zero(t, length)

	// add two streams
	mockCtrl := gomock.NewController(t)
	str1 := NewMockStreamFrameGetter(mockCtrl)
	str1.EXPECT().priority().Return(defaultUrgency, true, uint32(0)).AnyTimes()
	str1.EXPECT().popStreamFrame(gomock.Any(), protocol.Version1).Return(ackhandler.StreamFrame{Frame: f1}, nil, true)
	str2 := NewMockStreamFrameGetter(mockCtrl)
	str2.EXPECT().priority().Return(defaultUrgency, true, uint32(0)).AnyTimes()
	str2.EXPECT().popStreamFrame(gomock.Any(), protocol.Version1).Return(ackhandler.StreamFrame{Frame: f2}, nil, false)
	framer.AddActiveStream(str1ID, str1)
	framer.AddActiveStream(str1ID, str1) // duplicate calls are ok (they're no-ops)
	framer.AddActiveStream(str2ID, str2)
	require.True(t, framer.HasData())

	// Even though the first stream claimed to have more data,
	// we only dequeue a single STREAM frame per call of AppendStreamFrames.
	f0 := ackhandler.StreamFrame{Frame: &wire.StreamFrame{StreamID: 9999}}
	controlFrames, fs, length = framer.Append([]ackhandler.Frame{}, []ackhandler.StreamFrame{f0}, protocol.MaxByteCount, monotime.Now(), protocol.Version1)
	require.Empty(t, controlFrames)
	require.Len(t, fs, 3)
	require.Equal(t, f0, fs[0])
	require.Equal(t, str1ID, fs[1].Frame.StreamID)
	require.Equal(t, []byte("foo"), fs[1].Frame.Data)
	// since two STREAM frames are sent, the DataLenPresent flag is set on the first frame
	require.True(t, fs[1].Frame.DataLenPresent)
	require.Equal(t, str2ID, fs[2].Frame.StreamID)
	require.Equal(t, []byte("bar"), fs[2].Frame.Data)
	// the last frame doesn't have the DataLenPresent flag set
	require.False(t, fs[2].Frame.DataLenPresent)
	require.Equal(t, fs[1].Frame.Length(protocol.Version1)+fs[2].Frame.Length(protocol.Version1), length)
	require.Less(t, length, totalLen) // unsetting DataLenPresent on the last frame reduces the length
	require.True(t, framer.HasData()) // the stream claimed to have more data...

	// ... but it actually doesn't
	str1.EXPECT().popStreamFrame(gomock.Any(), protocol.Version1).Return(ackhandler.StreamFrame{}, nil, false)
	_, fs, length = framer.Append(nil, nil, protocol.MaxByteCount, monotime.Now(), protocol.Version1)
	require.Empty(t, fs)
	require.Zero(t, length)
	require.False(t, framer.HasData())
}

func TestFramerPrioritizesStreamRetransmissions(t *testing.T) {
	const (
		newDataStreamID       = protocol.StreamID(1)
		firstRetransStreamID  = protocol.StreamID(4)
		secondRetransStreamID = protocol.StreamID(8)
	)
	newDataStr := NewMockStreamFrameGetter(gomock.NewController(t))
	newDataStr.EXPECT().priority().Return(defaultUrgency, true, uint32(0)).AnyTimes()
	str1 := NewMockStreamFrameGetter(gomock.NewController(t))
	str1.EXPECT().priority().Return(defaultUrgency, true, uint32(0)).AnyTimes()
	str2 := NewMockStreamFrameGetter(gomock.NewController(t))
	str2.EXPECT().priority().Return(defaultUrgency, true, uint32(0)).AnyTimes()
	firstRetransmission := &wire.StreamFrame{StreamID: firstRetransStreamID, Data: []byte("first"), DataLenPresent: true}
	secondRetransmission := &wire.StreamFrame{StreamID: secondRetransStreamID, Data: []byte("second"), DataLenPresent: true}
	thirdRetransmission := &wire.StreamFrame{StreamID: secondRetransStreamID, Offset: 6, Data: []byte("third"), DataLenPresent: true}
	newData := &wire.StreamFrame{StreamID: newDataStreamID, Data: []byte("new"), DataLenPresent: true}

	str1.EXPECT().popRetransmissionFrame(gomock.Any(), protocol.Version1).Return(ackhandler.StreamFrame{Frame: firstRetransmission}, false)
	str2.EXPECT().popRetransmissionFrame(gomock.Any(), protocol.Version1).Return(ackhandler.StreamFrame{Frame: secondRetransmission}, true)
	str2.EXPECT().popRetransmissionFrame(gomock.Any(), protocol.Version1).Return(ackhandler.StreamFrame{Frame: thirdRetransmission}, false)
	newDataStr.EXPECT().popStreamFrame(gomock.Any(), protocol.Version1).Return(ackhandler.StreamFrame{Frame: newData}, nil, false)

	framer := newFramer(newConnectionFlowController(0, 0, nil, nil, nil))
	require.False(t, framer.HasData())
	framer.AddStreamWithRetransmission(secondRetransStreamID, str2)
	require.True(t, framer.HasData())
	framer.AddStreamWithRetransmission(secondRetransStreamID, str2) // duplicate calls are no-ops
	framer.AddActiveStream(newDataStreamID, newDataStr)
	framer.AddStreamWithRetransmission(firstRetransStreamID, str1)

	_, fs, _ := framer.Append(nil, nil, protocol.MaxByteCount, monotime.Now(), protocol.Version1)
	require.Len(t, fs, 4)
	require.Equal(t,
		[]protocol.StreamID{secondRetransStreamID, secondRetransStreamID, firstRetransStreamID, newDataStreamID},
		[]protocol.StreamID{fs[0].Frame.StreamID, fs[1].Frame.StreamID, fs[2].Frame.StreamID, fs[3].Frame.StreamID},
	)
	require.False(t, framer.HasData())
}

func TestFramerSplitsStreamRetransmissions(t *testing.T) {
	const (
		firstStreamID  = protocol.StreamID(4)
		secondStreamID = protocol.StreamID(8)
		maxLen         = protocol.ByteCount(1000)
	)
	str1 := NewMockStreamFrameGetter(gomock.NewController(t))
	str1.EXPECT().priority().Return(defaultUrgency, true, uint32(0)).AnyTimes()
	str2 := NewMockStreamFrameGetter(gomock.NewController(t))
	str2.EXPECT().priority().Return(defaultUrgency, true, uint32(0)).AnyTimes()
	data1 := bytes.Repeat([]byte{1}, 500)
	data2 := bytes.Repeat([]byte{2}, 1000)
	retransmit1 := &wire.StreamFrame{StreamID: firstStreamID, Data: data1, DataLenPresent: true}
	retransmit2 := &wire.StreamFrame{StreamID: secondStreamID, Data: data2, DataLenPresent: true}

	str1.EXPECT().popRetransmissionFrame(gomock.Any(), protocol.Version1).Return(ackhandler.StreamFrame{Frame: retransmit1}, false)
	str2.EXPECT().popRetransmissionFrame(gomock.Any(), protocol.Version1).DoAndReturn(func(maxSize protocol.ByteCount, v protocol.Version) (ackhandler.StreamFrame, bool) {
		f, split := retransmit2.MaybeSplitOffFrame(maxSize, v)
		require.True(t, split)
		return ackhandler.StreamFrame{Frame: f}, true
	})
	str2.EXPECT().popRetransmissionFrame(gomock.Any(), protocol.Version1).Return(ackhandler.StreamFrame{Frame: retransmit2}, false)

	framer := newFramer(newConnectionFlowController(0, 0, nil, nil, nil))
	framer.AddStreamWithRetransmission(firstStreamID, str1)
	framer.AddStreamWithRetransmission(secondStreamID, str2)

	_, fs, length := framer.Append(nil, nil, maxLen, monotime.Now(), protocol.Version1)
	require.Equal(t, maxLen, length)
	require.Len(t, fs, 2)
	require.Equal(t, firstStreamID, fs[0].Frame.StreamID)
	require.Len(t, fs[0].Frame.Data, len(data1))
	require.Equal(t, secondStreamID, fs[1].Frame.StreamID)
	require.Equal(t, protocol.ByteCount(0), fs[1].Frame.Offset)
	firstPartLen := len(fs[1].Frame.Data)
	require.Less(t, firstPartLen, len(data2))
	require.True(t, framer.HasData())

	_, fs, _ = framer.Append(nil, nil, maxLen, monotime.Now(), protocol.Version1)
	require.Len(t, fs, 1)
	require.Equal(t, secondStreamID, fs[0].Frame.StreamID)
	require.Equal(t, protocol.ByteCount(firstPartLen), fs[0].Frame.Offset)
	require.Len(t, fs[0].Frame.Data, len(data2)-firstPartLen)
	require.False(t, framer.HasData())
}

// newMockPriorityStream creates a mock stream that produces packet-sized frames at the given priority
func newMockPriorityStream(t *testing.T, id protocol.StreamID, urgency int8, incremental bool, numFrames int) *MockStreamFrameGetter {
	t.Helper()

	str := NewMockStreamFrameGetter(gomock.NewController(t))
	str.EXPECT().priority().Return(urgency, incremental, uint32(0)).AnyTimes()
	remaining := numFrames
	str.EXPECT().popStreamFrame(gomock.Any(), protocol.Version1).DoAndReturn(
		func(_ protocol.ByteCount, v protocol.Version) (ackhandler.StreamFrame, *wire.StreamDataBlockedFrame, bool) {
			frame := &wire.StreamFrame{StreamID: id, DataLenPresent: true}
			frame.Data = make([]byte, frame.MaxDataLen(protocol.MinStreamFrameSize, v))
			remaining--
			return ackhandler.StreamFrame{Frame: frame}, nil, remaining > 0
		},
	).Times(numFrames)
	return str
}

// appendPriorityPackets appends one STREAM frame per packet and returns their stream IDs.
func appendPriorityPackets(t *testing.T, framer *framer, numPackets int) []protocol.StreamID {
	t.Helper()

	ids := make([]protocol.StreamID, 0, numPackets)
	for range numPackets {
		_, frames, _ := framer.Append(nil, nil, protocol.MinStreamFrameSize, monotime.Now(), protocol.Version1)
		require.Len(t, frames, 1)
		ids = append(ids, frames[0].Frame.StreamID)
	}
	return ids
}

func TestFramerSchedulesIncrementalStreams(t *testing.T) {
	framer := newFramer(newConnectionFlowController(0, 0, nil, nil, nil))
	framer.AddActiveStream(8, newMockPriorityStream(t, 8, 0, true, 3))
	framer.AddActiveStream(0, newMockPriorityStream(t, 0, 1, true, 1))
	framer.AddActiveStream(4, newMockPriorityStream(t, 4, 0, true, 2))

	require.Equal(t,
		[]protocol.StreamID{8, 4, 8, 4, 8, 0},
		appendPriorityPackets(t, framer, 6),
	)
	require.False(t, framer.HasData())
}

func TestFramerSchedulesNonIncrementalStreams(t *testing.T) {
	framer := newFramer(newConnectionFlowController(0, 0, nil, nil, nil))
	framer.AddActiveStream(8, newMockPriorityStream(t, 8, 0, false, 2))
	framer.AddActiveStream(0, newMockPriorityStream(t, 0, 1, false, 1))
	framer.AddActiveStream(4, newMockPriorityStream(t, 4, 0, false, 3))

	require.Equal(t,
		[]protocol.StreamID{4, 4, 4, 8, 8, 0},
		appendPriorityPackets(t, framer, 6),
	)
	require.False(t, framer.HasData())
}

func TestFramerSchedulesReprioritizedStream(t *testing.T) {
	const updatedStreamID = protocol.StreamID(8)
	framer := newFramer(newConnectionFlowController(0, 0, nil, nil, nil))
	framer.AddActiveStream(4, newMockPriorityStream(t, 4, 1, true, 1))
	framer.AddActiveStream(12, newMockPriorityStream(t, 12, 2, true, 1))

	// stream 8 starts at urgency 0 with enough data for two packets
	updatedStr := NewMockStreamFrameGetter(gomock.NewController(t))
	gomock.InOrder(
		updatedStr.EXPECT().priority().Return(0, true, 0).Times(2),
		updatedStr.EXPECT().priority().Return(2, false, 1).Times(3),
	)
	remaining := 2
	updatedStr.EXPECT().popStreamFrame(gomock.Any(), protocol.Version1).DoAndReturn(
		func(_ protocol.ByteCount, v protocol.Version) (ackhandler.StreamFrame, *wire.StreamDataBlockedFrame, bool) {
			frame := &wire.StreamFrame{StreamID: updatedStreamID, DataLenPresent: true}
			frame.Data = make([]byte, frame.MaxDataLen(protocol.MinStreamFrameSize, v))
			remaining--
			return ackhandler.StreamFrame{Frame: frame}, nil, remaining > 0
		},
	).Times(2)
	framer.AddActiveStream(updatedStreamID, updatedStr)

	// the first packet contains stream 8 and leaves it queued at urgency 0
	ids := appendPriorityPackets(t, framer, 1)
	// lower stream 8 to urgency 2 and make it non-incremental, leaving its old queue entry stale
	framer.UpdateStreamPriority(updatedStreamID)
	ids = append(ids, appendPriorityPackets(t, framer, 3)...)

	// the stale entry is skipped, so stream 4 runs next; without the update, stream 8 would run next
	// at urgency 2, incremental stream 12 is scheduled before non-incremental stream 8
	require.Equal(t, []protocol.StreamID{8, 4, 12, 8}, ids)
	require.False(t, framer.HasData())
}

func TestFramerAlternatesIncrementalAndNonIncrementalStreams(t *testing.T) {
	framer := newFramer(newConnectionFlowController(0, 0, nil, nil, nil))
	framer.AddActiveStream(8, newMockPriorityStream(t, 8, 0, true, 2))
	framer.AddActiveStream(4, newMockPriorityStream(t, 4, 0, false, 3))
	framer.AddActiveStream(12, newMockPriorityStream(t, 12, 0, true, 1))

	// incremental streams 8 and 12 round-robin while stream 4 gets every non-incremental turn
	require.Equal(t,
		[]protocol.StreamID{8, 4, 12, 4, 8, 4},
		appendPriorityPackets(t, framer, 6),
	)
	require.False(t, framer.HasData())
}

func TestFramerRequeuesRetransmissionAfterPriorityChange(t *testing.T) {
	const streamID = protocol.StreamID(4)
	urgency := int8(3)
	str := NewMockStreamFrameGetter(gomock.NewController(t))
	str.EXPECT().priority().DoAndReturn(func() (int8, bool, uint32) {
		return urgency, true, 0
	}).AnyTimes()
	str.EXPECT().popRetransmissionFrame(gomock.Any(), protocol.Version1).Return(
		ackhandler.StreamFrame{Frame: &wire.StreamFrame{StreamID: streamID}}, false,
	)

	framer := newFramer(newConnectionFlowController(0, 0, nil, nil, nil))
	framer.AddStreamWithRetransmission(streamID, str)
	urgency = 2
	_, frames, _ := framer.Append(nil, nil, protocol.MaxByteCount, monotime.Now(), protocol.Version1)
	require.Empty(t, frames)
	require.True(t, framer.HasData())

	_, frames, _ = framer.Append(nil, nil, protocol.MaxByteCount, monotime.Now(), protocol.Version1)
	require.Len(t, frames, 1)
	require.Equal(t, streamID, frames[0].Frame.StreamID)
	require.False(t, framer.HasData())
}

func TestFramerUpdatesStreamRetransmissionPriority(t *testing.T) {
	const (
		updatedStreamID = protocol.StreamID(4)
		otherStreamID   = protocol.StreamID(8)
	)
	urgency := int8(0)
	updatedStr := NewMockStreamFrameGetter(gomock.NewController(t))
	updatedStr.EXPECT().priority().DoAndReturn(func() (int8, bool, uint32) {
		return urgency, true, 0
	}).AnyTimes()
	otherStr := NewMockStreamFrameGetter(gomock.NewController(t))
	otherStr.EXPECT().priority().Return(int8(1), true, uint32(0)).AnyTimes()
	updatedStr.EXPECT().popRetransmissionFrame(gomock.Any(), protocol.Version1).Return(
		ackhandler.StreamFrame{Frame: &wire.StreamFrame{StreamID: updatedStreamID}}, false,
	)
	otherStr.EXPECT().popRetransmissionFrame(gomock.Any(), protocol.Version1).Return(
		ackhandler.StreamFrame{Frame: &wire.StreamFrame{StreamID: otherStreamID}}, false,
	)

	framer := newFramer(newConnectionFlowController(0, 0, nil, nil, nil))
	framer.AddStreamWithRetransmission(updatedStreamID, updatedStr)
	framer.AddStreamWithRetransmission(otherStreamID, otherStr)
	urgency = 2
	_, frames, _ := framer.Append(nil, nil, protocol.MaxByteCount, monotime.Now(), protocol.Version1)
	require.Len(t, frames, 2)
	require.Equal(t, otherStreamID, frames[0].Frame.StreamID)
	require.Equal(t, updatedStreamID, frames[1].Frame.StreamID)
}

func TestFramerRemoveActiveStream(t *testing.T) {
	t.Run("incremental", func(t *testing.T) {
		testFramerRemoveActiveStream(t, true)
	})
	t.Run("non-incremental", func(t *testing.T) {
		testFramerRemoveActiveStream(t, false)
	})
}

// testFramerRemoveActiveStream verifies that queued data is discarded when a stream is removed.
func testFramerRemoveActiveStream(t *testing.T, incremental bool) {
	const id = protocol.StreamID(42)
	framer := newFramer(newConnectionFlowController(0, 0, nil, nil, nil))
	require.False(t, framer.HasData())
	str := NewMockStreamFrameGetter(gomock.NewController(t))
	str.EXPECT().priority().Return(defaultUrgency, incremental, uint32(0)).AnyTimes()
	framer.AddActiveStream(id, str)
	framer.AddStreamWithRetransmission(id, str)
	require.True(t, framer.HasData())
	framer.RemoveActiveStream(id) // no calls will be issued to the mock stream
	// we can't assert on framer.HasData here, since it's not removed from the scheduling queue
	_, frames, _ := framer.Append(nil, nil, protocol.MaxByteCount, monotime.Now(), protocol.Version1)
	require.Empty(t, frames)
	require.False(t, framer.HasData())
}

func TestFramerMinStreamFrameSize(t *testing.T) {
	const id = protocol.StreamID(42)
	framer := newFramer(newConnectionFlowController(0, 0, nil, nil, nil))
	str := NewMockStreamFrameGetter(gomock.NewController(t))
	str.EXPECT().priority().Return(defaultUrgency, true, uint32(0)).AnyTimes()
	framer.AddActiveStream(id, str)

	require.True(t, framer.HasData())
	// don't pop frames smaller than the minimum STREAM frame size
	_, frames, _ := framer.Append(nil, nil, protocol.MinStreamFrameSize-1, monotime.Now(), protocol.Version1)
	require.Empty(t, frames)

	// pop frames of the minimum size
	str.EXPECT().popStreamFrame(gomock.Any(), protocol.Version1).DoAndReturn(
		func(size protocol.ByteCount, v protocol.Version) (ackhandler.StreamFrame, *wire.StreamDataBlockedFrame, bool) {
			f := &wire.StreamFrame{StreamID: id, DataLenPresent: true}
			f.Data = make([]byte, f.MaxDataLen(protocol.MinStreamFrameSize, v))
			return ackhandler.StreamFrame{Frame: f}, nil, false
		},
	)
	_, frames, _ = framer.Append(nil, nil, protocol.MinStreamFrameSize, monotime.Now(), protocol.Version1)
	require.Len(t, frames, 1)
	// unsetting DataLenPresent on the last frame reduced the size slightly beyond the minimum size
	require.Equal(t, protocol.MinStreamFrameSize-2, frames[0].Frame.Length(protocol.Version1))
}

func TestFramerMinStreamFrameSizeMultipleStreamFrames(t *testing.T) {
	const id = protocol.StreamID(42)
	framer := newFramer(newConnectionFlowController(0, 0, nil, nil, nil))
	str := NewMockStreamFrameGetter(gomock.NewController(t))
	str.EXPECT().priority().Return(defaultUrgency, true, uint32(0)).AnyTimes()
	framer.AddActiveStream(id, str)

	// pop a frame such that the remaining size is one byte less than the minimum STREAM frame size
	f := &wire.StreamFrame{
		StreamID:       id,
		Data:           bytes.Repeat([]byte("f"), int(500-protocol.MinStreamFrameSize)),
		DataLenPresent: true,
	}
	str.EXPECT().popStreamFrame(gomock.Any(), protocol.Version1).Return(ackhandler.StreamFrame{Frame: f}, nil, false)
	framer.AddActiveStream(id, str)
	_, fs, length := framer.Append(nil, nil, 500, monotime.Now(), protocol.Version1)
	require.Len(t, fs, 1)
	require.Equal(t, f, fs[0].Frame)
	require.Equal(t, f.Length(protocol.Version1), length)
}

func TestFramerFillPacketOneStream(t *testing.T) {
	const id = protocol.StreamID(42)
	str := NewMockStreamFrameGetter(gomock.NewController(t))
	str.EXPECT().priority().Return(defaultUrgency, true, uint32(0)).AnyTimes()
	framer := newFramer(newConnectionFlowController(0, 0, nil, nil, nil))

	for i := protocol.MinStreamFrameSize; i < 2000; i++ {
		str.EXPECT().popStreamFrame(gomock.Any(), protocol.Version1).DoAndReturn(
			func(size protocol.ByteCount, v protocol.Version) (ackhandler.StreamFrame, *wire.StreamDataBlockedFrame, bool) {
				f := &wire.StreamFrame{
					StreamID:       id,
					DataLenPresent: true,
				}
				f.Data = make([]byte, f.MaxDataLen(size, v))
				require.Equal(t, size, f.Length(protocol.Version1))
				return ackhandler.StreamFrame{Frame: f}, nil, false
			},
		)
		framer.AddActiveStream(id, str)
		_, frames, _ := framer.Append(nil, nil, i, monotime.Now(), protocol.Version1)
		require.Len(t, frames, 1)
		require.False(t, frames[0].Frame.DataLenPresent)
		// make sure the entire space was filled up
		require.Equal(t, i, frames[0].Frame.Length(protocol.Version1))
	}
}

func TestFramerFillPacketMultipleStreams(t *testing.T) {
	const (
		id1 = protocol.StreamID(1000)
		id2 = protocol.StreamID(11)
	)
	mockCtrl := gomock.NewController(t)
	str1 := NewMockStreamFrameGetter(mockCtrl)
	str1.EXPECT().priority().Return(defaultUrgency, true, uint32(0)).AnyTimes()
	str2 := NewMockStreamFrameGetter(mockCtrl)
	str2.EXPECT().priority().Return(defaultUrgency, true, uint32(0)).AnyTimes()
	framer := newFramer(newConnectionFlowController(0, 0, nil, nil, nil))

	for i := 2 * protocol.MinStreamFrameSize; i < 2000; i++ {
		str1.EXPECT().popStreamFrame(gomock.Any(), protocol.Version1).DoAndReturn(
			func(size protocol.ByteCount, v protocol.Version) (ackhandler.StreamFrame, *wire.StreamDataBlockedFrame, bool) {
				f := &wire.StreamFrame{StreamID: id1, DataLenPresent: true}
				f.Data = make([]byte, f.MaxDataLen(protocol.MinStreamFrameSize, v))
				return ackhandler.StreamFrame{Frame: f}, nil, false
			},
		)
		str2.EXPECT().popStreamFrame(gomock.Any(), protocol.Version1).DoAndReturn(
			func(size protocol.ByteCount, v protocol.Version) (ackhandler.StreamFrame, *wire.StreamDataBlockedFrame, bool) {
				f := &wire.StreamFrame{StreamID: id2, DataLenPresent: true}
				f.Data = make([]byte, f.MaxDataLen(size, v))
				require.Equal(t, size, f.Length(protocol.Version1))
				return ackhandler.StreamFrame{Frame: f}, nil, false
			},
		)
		framer.AddActiveStream(id1, str1)
		framer.AddActiveStream(id2, str2)
		_, frames, _ := framer.Append(nil, nil, i, monotime.Now(), protocol.Version1)
		require.Len(t, frames, 2)
		require.True(t, frames[0].Frame.DataLenPresent)
		require.False(t, frames[1].Frame.DataLenPresent)
		require.Equal(t, i, frames[0].Frame.Length(protocol.Version1)+frames[1].Frame.Length(protocol.Version1))
	}
}

func TestFramer0RTTRejection(t *testing.T) {
	ncid := &wire.NewConnectionIDFrame{
		SequenceNumber: 10,
		ConnectionID:   protocol.ParseConnectionID([]byte{0xde, 0xad, 0xbe, 0xef}),
	}
	ping := &wire.PingFrame{}
	pc := &wire.PathChallengeFrame{Data: [8]byte{1, 2, 3, 4, 6, 7, 8}}

	framer := newFramer(newConnectionFlowController(0, 0, nil, nil, nil))
	framer.QueueControlFrame(ncid)
	framer.QueueControlFrame(&wire.DataBlockedFrame{MaximumData: 1337})
	framer.QueueControlFrame(&wire.StreamDataBlockedFrame{StreamID: 42, MaximumStreamData: 1337})
	framer.QueueControlFrame(ping)
	framer.QueueControlFrame(&wire.StreamsBlockedFrame{StreamLimit: 13})
	framer.QueueControlFrame(pc)

	str := NewMockStreamFrameGetter(gomock.NewController(t))
	str.EXPECT().priority().Return(defaultUrgency, true, uint32(0)).AnyTimes()
	framer.AddActiveStream(10, str)
	framer.AddStreamWithRetransmission(10, str)
	framer.AddStreamWithControlFrames(10, NewMockStreamControlFrameGetter(gomock.NewController(t)))

	framer.Handle0RTTRejection()
	controlFrames, streamFrames, _ := framer.Append(nil, nil, protocol.MaxByteCount, monotime.Now(), protocol.Version1)
	require.Empty(t, streamFrames)
	require.Len(t, controlFrames, 3)
	require.Contains(t, controlFrames, ackhandler.Frame{Frame: pc})
	require.Contains(t, controlFrames, ackhandler.Frame{Frame: ping})
	require.Contains(t, controlFrames, ackhandler.Frame{Frame: ncid})
}
