package flowcontrol

import (
	"testing"
	"time"

	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/qerr"
	"github.com/quic-go/quic-go/internal/utils"

	"github.com/stretchr/testify/require"
)

func TestStreamFlowControlReceiving(t *testing.T) {
	fc := NewStreamFlowController(
		42,
		NewConnectionFlowController(
			protocol.MaxByteCount,
			protocol.MaxByteCount,
			nil,
			&utils.RTTStats{},
			utils.DefaultLogger,
		),
		100,
		protocol.MaxByteCount,
		protocol.MaxByteCount,
		&utils.RTTStats{},
		utils.DefaultLogger,
	)

	require.NoError(t, fc.UpdateHighestReceived(50, false, time.Now()))
	// duplicates are fine
	require.NoError(t, fc.UpdateHighestReceived(50, false, time.Now()))
	// reordering is fine
	require.NoError(t, fc.UpdateHighestReceived(40, false, time.Now()))
	require.NoError(t, fc.UpdateHighestReceived(60, false, time.Now()))

	// exceeding the limit is not fine
	err := fc.UpdateHighestReceived(101, false, time.Now())
	var terr *qerr.TransportError
	require.ErrorAs(t, err, &terr)
	require.Equal(t, qerr.FlowControlError, terr.ErrorCode)
	require.Equal(t, "received 101 bytes on stream 42, allowed 100 bytes", terr.ErrorMessage)
}

func TestStreamFlowControllerFinalOffset(t *testing.T) {
	newFC := func() StreamFlowController {
		return NewStreamFlowController(
			42,
			NewConnectionFlowController(
				protocol.MaxByteCount,
				protocol.MaxByteCount,
				nil,
				&utils.RTTStats{},
				utils.DefaultLogger,
			),
			protocol.MaxByteCount,
			protocol.MaxByteCount,
			protocol.MaxByteCount,
			&utils.RTTStats{},
			utils.DefaultLogger,
		)
	}

	t.Run("duplicate final offset", func(t *testing.T) {
		fc := newFC()
		require.NoError(t, fc.UpdateHighestReceived(50, true, time.Now()))
		// it is valid to receive the same final offset multiple times
		require.NoError(t, fc.UpdateHighestReceived(50, true, time.Now()))
	})

	t.Run("inconsistent final offset", func(t *testing.T) {
		fc := newFC()
		require.NoError(t, fc.UpdateHighestReceived(50, true, time.Now()))
		err := fc.UpdateHighestReceived(51, true, time.Now())
		require.Error(t, err)
		var terr *qerr.TransportError
		require.ErrorAs(t, err, &terr)
		require.Equal(t, qerr.FinalSizeError, terr.ErrorCode)
		require.Equal(t, "received inconsistent final offset for stream 42 (old: 50, new: 51 bytes)", terr.ErrorMessage)
	})

	t.Run("non-final offset past final offset", func(t *testing.T) {
		fc := newFC()
		require.NoError(t, fc.UpdateHighestReceived(50, true, time.Now()))
		// No matter the ordering, it's never ok to receive an offset past the final offset.
		err := fc.UpdateHighestReceived(60, false, time.Now())
		var terr *qerr.TransportError
		require.ErrorAs(t, err, &terr)
		require.Equal(t, qerr.FinalSizeError, terr.ErrorCode)
		require.Equal(t, "received offset 60 for stream 42, but final offset was already received at 50", terr.ErrorMessage)
	})

	t.Run("final offset smaller than previous offset", func(t *testing.T) {
		fc := newFC()
		require.NoError(t, fc.UpdateHighestReceived(50, false, time.Now()))
		// If we received offset already, it's invalid to receive a smaller final offset.
		err := fc.UpdateHighestReceived(40, true, time.Now())
		var terr *qerr.TransportError
		require.ErrorAs(t, err, &terr)
		require.Equal(t, qerr.FinalSizeError, terr.ErrorCode)
		require.Equal(t, "received final offset 40 for stream 42, but already received offset 50 before", terr.ErrorMessage)
	})
}

func TestStreamAbandoning(t *testing.T) {
	connFC := NewConnectionFlowController(
		100,
		protocol.MaxByteCount,
		nil,
		&utils.RTTStats{},
		utils.DefaultLogger,
	)
	require.True(t, connFC.UpdateSendWindow(300))
	fc := NewStreamFlowController(
		42,
		connFC,
		60,
		protocol.MaxByteCount,
		100,
		&utils.RTTStats{},
		utils.DefaultLogger,
	)

	require.NoError(t, fc.UpdateHighestReceived(50, true, time.Now()))
	require.Zero(t, fc.GetWindowUpdate(time.Now()))
	require.Zero(t, connFC.GetWindowUpdate(time.Now()))

	// Abandon the stream.
	// This marks all bytes as having been consumed.
	fc.Abandon()
	require.Equal(t, protocol.ByteCount(150), connFC.GetWindowUpdate(time.Now()))
}

func TestStreamSendWindow(t *testing.T) {
	// We set up the connection flow controller with a limit of 300 bytes,
	// and the stream flow controller with a limit of 100 bytes.
	connFC := NewConnectionFlowController(
		protocol.MaxByteCount,
		protocol.MaxByteCount,
		nil,
		&utils.RTTStats{},
		utils.DefaultLogger,
	)
	require.True(t, connFC.UpdateSendWindow(300))
	fc := NewStreamFlowController(
		42,
		connFC,
		protocol.MaxByteCount,
		protocol.MaxByteCount,
		100,
		&utils.RTTStats{},
		utils.DefaultLogger,
	)
	// first, we're limited by the stream flow controller
	require.Equal(t, protocol.ByteCount(100), fc.SendWindowSize())
	fc.AddBytesSent(50)
	require.False(t, fc.IsNewlyBlocked())
	require.Equal(t, protocol.ByteCount(50), fc.SendWindowSize())
	fc.AddBytesSent(50)
	require.True(t, fc.IsNewlyBlocked())
	require.Zero(t, fc.SendWindowSize())
	require.False(t, fc.IsNewlyBlocked()) // we're still blocked, but it's not new

	// Update the stream flow control limit, but don't update the connection flow control limit.
	// We're now limited by the connection flow controller.
	require.True(t, fc.UpdateSendWindow(1000))
	// reordered updates are ignored
	require.False(t, fc.UpdateSendWindow(999))

	require.False(t, fc.IsNewlyBlocked()) // we're not blocked anymore
	require.Equal(t, protocol.ByteCount(200), fc.SendWindowSize())
	fc.AddBytesSent(200)
	require.Zero(t, fc.SendWindowSize())
	require.False(t, fc.IsNewlyBlocked()) // we're blocked, but not on stream flow control
}

func TestStreamWindowUpdate(t *testing.T) {
	fc := NewStreamFlowController(
		42,
		NewConnectionFlowController(
			protocol.MaxByteCount,
			protocol.MaxByteCount,
			nil,
			&utils.RTTStats{},
			utils.DefaultLogger,
		),
		100,
		100,
		protocol.MaxByteCount,
		&utils.RTTStats{},
		utils.DefaultLogger,
	)
	require.Zero(t, fc.GetWindowUpdate(time.Now()))
	hasStreamWindowUpdate, _ := fc.AddBytesRead(24)
	require.False(t, hasStreamWindowUpdate)
	require.Zero(t, fc.GetWindowUpdate(time.Now()))
	// the window is updated when it's 25% filled
	hasStreamWindowUpdate, _ = fc.AddBytesRead(1)
	require.True(t, hasStreamWindowUpdate)
	require.Equal(t, protocol.ByteCount(125), fc.GetWindowUpdate(time.Now()))

	hasStreamWindowUpdate, _ = fc.AddBytesRead(24)
	require.False(t, hasStreamWindowUpdate)
	require.Zero(t, fc.GetWindowUpdate(time.Now()))
	// the window is updated when it's 25% filled
	hasStreamWindowUpdate, _ = fc.AddBytesRead(1)
	require.True(t, hasStreamWindowUpdate)
	require.Equal(t, protocol.ByteCount(150), fc.GetWindowUpdate(time.Now()))

	// Receive the final offset.
	// We don't need to send any more flow control updates.
	require.NoError(t, fc.UpdateHighestReceived(100, true, time.Now()))
	fc.AddBytesRead(50)
	require.Zero(t, fc.GetWindowUpdate(time.Now()))
}

func TestStreamConnectionWindowUpdate(t *testing.T) {
	connFC := NewConnectionFlowController(
		100,
		protocol.MaxByteCount,
		nil,
		&utils.RTTStats{},
		utils.DefaultLogger,
	)
	fc := NewStreamFlowController(
		42,
		connFC,
		1000,
		protocol.MaxByteCount,
		protocol.MaxByteCount,
		&utils.RTTStats{},
		utils.DefaultLogger,
	)

	hasStreamWindowUpdate, hasConnWindowUpdate := fc.AddBytesRead(50)
	require.False(t, hasStreamWindowUpdate)
	require.Zero(t, fc.GetWindowUpdate(time.Now()))
	require.True(t, hasConnWindowUpdate)
	require.NotZero(t, connFC.GetWindowUpdate(time.Now()))
}

func TestStreamWindowAutoTuning(t *testing.T) {
	// the RTT is 1 second
	rttStats := &utils.RTTStats{}
	rttStats.UpdateRTT(time.Second, 0)
	require.Equal(t, time.Second, rttStats.SmoothedRTT())

	connFC := NewConnectionFlowController(
		150, // initial receive window
		350, // max receive window
		func(size protocol.ByteCount) bool { return true },
		rttStats,
		utils.DefaultLogger,
	)
	fc := NewStreamFlowController(
		42,
		connFC,
		100, // initial send window
		399, // max send window
		protocol.MaxByteCount,
		rttStats,
		utils.DefaultLogger,
	)

	now := time.Now()
	require.NoError(t, fc.UpdateHighestReceived(100, false, now))

	// data consumption is too slow, window size is not increased
	now = now.Add(2500 * time.Millisecond)
	fc.AddBytesRead(51)
	// one initial stream window size added
	require.Equal(t, protocol.ByteCount(51+100), fc.GetWindowUpdate(now))
	// one initial connection window size added
	require.Equal(t, protocol.ByteCount(51+150), connFC.getWindowUpdate(now))

	// data consumption is fast enough, window size is increased
	now = now.Add(2 * time.Second)
	fc.AddBytesRead(51)
	// stream window size doubled to 200 bytes
	require.Equal(t, protocol.ByteCount(102+2*100), fc.GetWindowUpdate(now))
	// The connection window is now increased as well,
	// so that we don't get blocked on connection level flow control:
	// The increase is by 200 bytes * a connection factor of 1.5: 300 bytes.
	require.Equal(t, protocol.ByteCount(102+300), connFC.GetWindowUpdate(now))

	// data consumption is fast enough, window size is increased
	now = now.Add(2 * time.Second)
	fc.AddBytesRead(101)
	// stream window size increased again, but bumps into its maximum value
	require.Equal(t, protocol.ByteCount(203+399), fc.GetWindowUpdate(now))
	// the connection window is also increased, but it bumps into its maximum value
	require.Equal(t, protocol.ByteCount(203+350), connFC.GetWindowUpdate(now))
}
