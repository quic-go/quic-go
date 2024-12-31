package quic

import (
	"bytes"
	"testing"
	"time"

	"golang.org/x/exp/rand"

	"github.com/quic-go/quic-go/internal/ackhandler"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/wire"

	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

func TestFramerControlFrames(t *testing.T) {
	pc := &wire.PathChallengeFrame{Data: [8]byte{1, 2, 3, 4, 6, 7, 8}}
	msf := &wire.MaxStreamsFrame{MaxStreamNum: 0x1337}

	framer := newFramer()
	require.False(t, framer.HasData())
	framer.QueueControlFrame(pc)
	require.True(t, framer.HasData())
	framer.QueueControlFrame(msf)
	frames, length := framer.AppendControlFrames(
		[]ackhandler.Frame{{Frame: &wire.PingFrame{}}},
		protocol.MaxByteCount,
		time.Now(),
		protocol.Version1,
	)
	require.Len(t, frames, 3)
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

	framer := newFramer()
	numFrames := int(maxSize / bfLen) // max number of frames that fit into maxSize
	for i := 0; i < numFrames+1; i++ {
		framer.QueueControlFrame(bf)
	}
	frames, length := framer.AppendControlFrames(nil, maxSize, time.Now(), protocol.Version1)
	require.Len(t, frames, numFrames)
	require.Greater(t, length, maxSize-bfLen)
	// now make sure that the last frame is also added
	frames, length = framer.AppendControlFrames(nil, maxSize, time.Now(), protocol.Version1)
	require.Len(t, frames, 1)
	require.Equal(t, length, bfLen)
}

func TestFramerStreamControlFrames(t *testing.T) {
	const streamID = protocol.StreamID(10)
	ping := &wire.PingFrame{}
	mdf1 := &wire.MaxStreamDataFrame{StreamID: streamID, MaximumStreamData: 1337}
	mdf2 := &wire.MaxStreamDataFrame{StreamID: streamID, MaximumStreamData: 1338}

	framer := newFramer()
	framer.QueueControlFrame(ping)
	str := NewMockStreamControlFrameGetter(gomock.NewController(t))
	framer.AddStreamWithControlFrames(streamID, str)
	now := time.Now()
	str.EXPECT().getControlFrame(now).Return(ackhandler.Frame{Frame: mdf1}, true, true)
	str.EXPECT().getControlFrame(now).Return(ackhandler.Frame{Frame: mdf2}, true, false)
	frames, l := framer.AppendControlFrames(nil, protocol.MaxByteCount, now, protocol.Version1)
	require.Len(t, frames, 3)
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
	framer := newFramer()
	framer.AddStreamWithControlFrames(10, str)
	str.EXPECT().getControlFrame(gomock.Any()).Return(ackhandler.Frame{Frame: mdf1}, true, true).AnyTimes()
	frames, l := framer.AppendControlFrames(nil, 100, time.Now(), protocol.Version1)
	require.Equal(t, protocol.ByteCount(len(frames))*mdf1.Length(protocol.Version1), l)
	require.Greater(t, l, protocol.ByteCount(100-maxStreamControlFrameSize))
	require.LessOrEqual(t, l, protocol.ByteCount(100))
}

func TestFramerDetectsFrameDoS(t *testing.T) {
	framer := newFramer()
	for i := 0; i < maxControlFrames-1; i++ {
		framer.QueueControlFrame(&wire.PingFrame{})
		framer.QueueControlFrame(&wire.PingFrame{})
		require.False(t, framer.QueuedTooManyControlFrames())
		frames, _ := framer.AppendControlFrames([]ackhandler.Frame{}, 1, time.Now(), protocol.Version1)
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
	framer := newFramer()
	var pathResponses []*wire.PathResponseFrame
	for i := 0; i < 2*maxPathResponses; i++ {
		var f wire.PathResponseFrame
		rand.Read(f.Data[:])
		pathResponses = append(pathResponses, &f)
		framer.QueueControlFrame(&f)
	}
	for i := 0; i < maxPathResponses; i++ {
		require.True(t, framer.HasData())
		frames, length := framer.AppendControlFrames(nil, protocol.MaxByteCount, time.Now(), protocol.Version1)
		require.Len(t, frames, 1)
		require.Equal(t, pathResponses[i], frames[0].Frame)
		require.Equal(t, pathResponses[i].Length(protocol.Version1), length)
	}
	require.False(t, framer.HasData())
	frames, length := framer.AppendControlFrames(nil, protocol.MaxByteCount, time.Now(), protocol.Version1)
	require.Empty(t, frames)
	require.Zero(t, length)
}

func TestFramerPacksSinglePathResponsePerPacket(t *testing.T) {
	framer := newFramer()
	f1 := &wire.PathResponseFrame{Data: [8]byte{1, 2, 3, 4, 5, 6, 7, 8}}
	f2 := &wire.PathResponseFrame{Data: [8]byte{2, 3, 4, 5, 6, 7, 8, 9}}
	cf1 := &wire.DataBlockedFrame{MaximumData: 1337}
	cf2 := &wire.HandshakeDoneFrame{}
	framer.QueueControlFrame(f1)
	framer.QueueControlFrame(f2)
	framer.QueueControlFrame(cf1)
	framer.QueueControlFrame(cf2)
	// the first packet should contain a single PATH_RESPONSE frame, but all the other control frames
	frames, _ := framer.AppendControlFrames(nil, protocol.MaxByteCount, time.Now(), protocol.Version1)
	require.Len(t, frames, 3)
	require.Equal(t, f1, frames[0].Frame)
	require.Contains(t, []wire.Frame{frames[1].Frame, frames[2].Frame}, cf1)
	require.Contains(t, []wire.Frame{frames[1].Frame, frames[2].Frame}, cf2)
	// the second packet should contain the other PATH_RESPONSE frame
	require.True(t, framer.HasData())
	frames, _ = framer.AppendControlFrames(nil, protocol.MaxByteCount, time.Now(), protocol.Version1)
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

	framer := newFramer()
	require.False(t, framer.HasData())
	// no frames added yet
	fs, length := framer.AppendStreamFrames(nil, protocol.MaxByteCount, protocol.Version1)
	require.Empty(t, fs)
	require.Zero(t, length)

	// add two streams
	mockCtrl := gomock.NewController(t)
	str1 := NewMockSendStreamI(mockCtrl)
	str1.EXPECT().popStreamFrame(gomock.Any(), protocol.Version1).Return(ackhandler.StreamFrame{Frame: f1}, true)
	str2 := NewMockSendStreamI(mockCtrl)
	str2.EXPECT().popStreamFrame(gomock.Any(), protocol.Version1).Return(ackhandler.StreamFrame{Frame: f2}, false)
	framer.AddActiveStream(str1ID, str1)
	framer.AddActiveStream(str1ID, str1) // duplicate calls are ok (they're no-ops)
	framer.AddActiveStream(str2ID, str2)
	require.True(t, framer.HasData())

	// Even though the first stream claimed to have more data,
	// we only dequeue a single STREAM frame per call of AppendStreamFrames.
	f0 := ackhandler.StreamFrame{Frame: &wire.StreamFrame{StreamID: 9999}}
	fs, length = framer.AppendStreamFrames([]ackhandler.StreamFrame{f0}, protocol.MaxByteCount, protocol.Version1)
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
	str1.EXPECT().popStreamFrame(gomock.Any(), protocol.Version1).Return(ackhandler.StreamFrame{}, false)
	fs, length = framer.AppendStreamFrames(nil, protocol.MaxByteCount, protocol.Version1)
	require.Empty(t, fs)
	require.Zero(t, length)
	require.False(t, framer.HasData())
}

func TestFramerRemoveActiveStream(t *testing.T) {
	const id = protocol.StreamID(42)
	framer := newFramer()
	require.False(t, framer.HasData())
	framer.AddActiveStream(id, NewMockSendStreamI(gomock.NewController(t)))
	require.True(t, framer.HasData())
	framer.RemoveActiveStream(id) // no calls will be issued to the mock stream
	// we can't assert on framer.HasData here, since it's not removed from the ringbuffer
	frames, _ := framer.AppendStreamFrames(nil, protocol.MaxByteCount, protocol.Version1)
	require.Empty(t, frames)
	require.False(t, framer.HasData())
}

func TestFramerMinStreamFrameSize(t *testing.T) {
	const id = protocol.StreamID(42)
	framer := newFramer()
	str := NewMockSendStreamI(gomock.NewController(t))
	framer.AddActiveStream(id, str)

	require.True(t, framer.HasData())
	// don't pop frames smaller than the minimum STREAM frame size
	frames, _ := framer.AppendStreamFrames(nil, protocol.MinStreamFrameSize-1, protocol.Version1)
	require.Empty(t, frames)

	// pop frames of the minimum size
	str.EXPECT().popStreamFrame(gomock.Any(), protocol.Version1).DoAndReturn(
		func(size protocol.ByteCount, v protocol.Version) (ackhandler.StreamFrame, bool) {
			f := &wire.StreamFrame{StreamID: id, DataLenPresent: true}
			f.Data = make([]byte, f.MaxDataLen(protocol.MinStreamFrameSize, v))
			return ackhandler.StreamFrame{Frame: f}, false
		},
	)
	frames, _ = framer.AppendStreamFrames(nil, protocol.MinStreamFrameSize, protocol.Version1)
	require.Len(t, frames, 1)
	// unsetting DataLenPresent on the last frame reduced the size slightly beyond the minimum size
	require.Equal(t, protocol.MinStreamFrameSize-2, frames[0].Frame.Length(protocol.Version1))
}

func TestFramerMinStreamFrameSizeMultipleStreamFrames(t *testing.T) {
	const id = protocol.StreamID(42)
	framer := newFramer()
	str := NewMockSendStreamI(gomock.NewController(t))
	framer.AddActiveStream(id, str)

	// pop a frame such that the remaining size is one byte less than the minimum STREAM frame size
	f := &wire.StreamFrame{
		StreamID:       id,
		Data:           bytes.Repeat([]byte("f"), int(500-protocol.MinStreamFrameSize)),
		DataLenPresent: true,
	}
	str.EXPECT().popStreamFrame(gomock.Any(), protocol.Version1).Return(ackhandler.StreamFrame{Frame: f}, false)
	framer.AddActiveStream(id, str)
	fs, length := framer.AppendStreamFrames(nil, 500, protocol.Version1)
	require.Len(t, fs, 1)
	require.Equal(t, f, fs[0].Frame)
	require.Equal(t, f.Length(protocol.Version1), length)
}

func TestFramerFillPacketOneStream(t *testing.T) {
	const id = protocol.StreamID(42)
	str := NewMockSendStreamI(gomock.NewController(t))
	framer := newFramer()

	for i := protocol.MinStreamFrameSize; i < 2000; i++ {
		str.EXPECT().popStreamFrame(gomock.Any(), protocol.Version1).DoAndReturn(
			func(size protocol.ByteCount, v protocol.Version) (ackhandler.StreamFrame, bool) {
				f := &wire.StreamFrame{
					StreamID:       id,
					DataLenPresent: true,
				}
				f.Data = make([]byte, f.MaxDataLen(size, v))
				require.Equal(t, size, f.Length(protocol.Version1))
				return ackhandler.StreamFrame{Frame: f}, false
			},
		)
		framer.AddActiveStream(id, str)
		frames, _ := framer.AppendStreamFrames(nil, i, protocol.Version1)
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
	stream1 := NewMockSendStreamI(mockCtrl)
	stream2 := NewMockSendStreamI(mockCtrl)
	framer := newFramer()

	for i := 2 * protocol.MinStreamFrameSize; i < 2000; i++ {
		stream1.EXPECT().popStreamFrame(gomock.Any(), protocol.Version1).DoAndReturn(
			func(size protocol.ByteCount, v protocol.Version) (ackhandler.StreamFrame, bool) {
				f := &wire.StreamFrame{StreamID: id1, DataLenPresent: true}
				f.Data = make([]byte, f.MaxDataLen(protocol.MinStreamFrameSize, v))
				return ackhandler.StreamFrame{Frame: f}, false
			},
		)
		stream2.EXPECT().popStreamFrame(gomock.Any(), protocol.Version1).DoAndReturn(
			func(size protocol.ByteCount, v protocol.Version) (ackhandler.StreamFrame, bool) {
				f := &wire.StreamFrame{StreamID: id2, DataLenPresent: true}
				f.Data = make([]byte, f.MaxDataLen(size, v))
				require.Equal(t, size, f.Length(protocol.Version1))
				return ackhandler.StreamFrame{Frame: f}, false
			},
		)
		framer.AddActiveStream(id1, stream1)
		framer.AddActiveStream(id2, stream2)
		frames, _ := framer.AppendStreamFrames(nil, i, protocol.Version1)
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

	framer := newFramer()
	framer.QueueControlFrame(ncid)
	framer.QueueControlFrame(&wire.DataBlockedFrame{MaximumData: 1337})
	framer.QueueControlFrame(&wire.StreamDataBlockedFrame{StreamID: 42, MaximumStreamData: 1337})
	framer.QueueControlFrame(ping)
	framer.QueueControlFrame(&wire.StreamsBlockedFrame{StreamLimit: 13})
	framer.QueueControlFrame(pc)

	framer.AddActiveStream(10, NewMockSendStreamI(gomock.NewController(t)))

	framer.Handle0RTTRejection()
	streamFrames, _ := framer.AppendStreamFrames(nil, protocol.MaxByteCount, protocol.Version1)
	require.Empty(t, streamFrames)

	controlFrames, _ := framer.AppendControlFrames(nil, protocol.MaxByteCount, time.Now(), protocol.Version1)
	require.Len(t, controlFrames, 3)
	require.Contains(t, controlFrames, ackhandler.Frame{Frame: pc})
	require.Contains(t, controlFrames, ackhandler.Frame{Frame: ping})
	require.Contains(t, controlFrames, ackhandler.Frame{Frame: ncid})
}
