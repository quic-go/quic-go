package protocol

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestInvalidStreamIDSmallerThanAllValidStreamIDs(t *testing.T) {
	require.Less(t, InvalidStreamID, StreamID(0))
}

func TestStreamIDInitiatedBy(t *testing.T) {
	require.Equal(t, PerspectiveClient, StreamID(4).InitiatedBy())
	require.Equal(t, PerspectiveServer, StreamID(5).InitiatedBy())
	require.Equal(t, PerspectiveClient, StreamID(6).InitiatedBy())
	require.Equal(t, PerspectiveServer, StreamID(7).InitiatedBy())
}

func TestStreamIDType(t *testing.T) {
	require.Equal(t, StreamTypeBidi, StreamID(4).Type())
	require.Equal(t, StreamTypeBidi, StreamID(5).Type())
	require.Equal(t, StreamTypeUni, StreamID(6).Type())
	require.Equal(t, StreamTypeUni, StreamID(7).Type())
}

func TestStreamIDStreamNum(t *testing.T) {
	require.Equal(t, StreamNum(1), StreamID(0).StreamNum())
	require.Equal(t, StreamNum(1), StreamID(1).StreamNum())
	require.Equal(t, StreamNum(1), StreamID(2).StreamNum())
	require.Equal(t, StreamNum(1), StreamID(3).StreamNum())
	require.Equal(t, StreamNum(3), StreamID(8).StreamNum())
	require.Equal(t, StreamNum(3), StreamID(9).StreamNum())
	require.Equal(t, StreamNum(3), StreamID(10).StreamNum())
	require.Equal(t, StreamNum(3), StreamID(11).StreamNum())
}

func TestStreamIDNumToStreamID(t *testing.T) {
	// 1st stream
	require.Equal(t, StreamID(0), StreamNum(1).StreamID(StreamTypeBidi, PerspectiveClient))
	require.Equal(t, StreamID(1), StreamNum(1).StreamID(StreamTypeBidi, PerspectiveServer))
	require.Equal(t, StreamID(2), StreamNum(1).StreamID(StreamTypeUni, PerspectiveClient))
	require.Equal(t, StreamID(3), StreamNum(1).StreamID(StreamTypeUni, PerspectiveServer))

	// 100th stream
	require.Equal(t, StreamID(396), StreamNum(100).StreamID(StreamTypeBidi, PerspectiveClient))
	require.Equal(t, StreamID(397), StreamNum(100).StreamID(StreamTypeBidi, PerspectiveServer))
	require.Equal(t, StreamID(398), StreamNum(100).StreamID(StreamTypeUni, PerspectiveClient))
	require.Equal(t, StreamID(399), StreamNum(100).StreamID(StreamTypeUni, PerspectiveServer))

	// 0 is not a valid stream number
	require.Equal(t, InvalidStreamID, StreamNum(0).StreamID(StreamTypeBidi, PerspectiveClient))
	require.Equal(t, InvalidStreamID, StreamNum(0).StreamID(StreamTypeBidi, PerspectiveServer))
	require.Equal(t, InvalidStreamID, StreamNum(0).StreamID(StreamTypeUni, PerspectiveClient))
	require.Equal(t, InvalidStreamID, StreamNum(0).StreamID(StreamTypeUni, PerspectiveServer))
}

func TestMaxStreamCountValue(t *testing.T) {
	const maxStreamID = StreamID(1<<62 - 1)
	for _, dir := range []StreamType{StreamTypeUni, StreamTypeBidi} {
		for _, pers := range []Perspective{PerspectiveClient, PerspectiveServer} {
			require.LessOrEqual(t, MaxStreamCount.StreamID(dir, pers), maxStreamID)
			require.Greater(t, (MaxStreamCount+1).StreamID(dir, pers), maxStreamID)
		}
	}
}
