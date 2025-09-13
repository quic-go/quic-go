package quic

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/quic-go/quic-go/internal/flowcontrol"
	"github.com/quic-go/quic-go/internal/mocks"
	"github.com/quic-go/quic-go/internal/monotime"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/qerr"
	"github.com/quic-go/quic-go/internal/wire"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

func TestStreamsMapCreatingStreams(t *testing.T) {
	t.Run("client", func(t *testing.T) {
		testStreamsMapCreatingStreams(t, protocol.PerspectiveClient,
			protocol.FirstIncomingBidiStreamClient,
			protocol.FirstOutgoingBidiStreamClient,
			protocol.FirstIncomingUniStreamClient,
			protocol.FirstOutgoingUniStreamClient,
		)
	})
	t.Run("server", func(t *testing.T) {
		testStreamsMapCreatingStreams(t, protocol.PerspectiveServer,
			protocol.FirstIncomingBidiStreamServer,
			protocol.FirstOutgoingBidiStreamServer,
			protocol.FirstIncomingUniStreamServer,
			protocol.FirstOutgoingUniStreamServer,
		)
	})
}

func testStreamsMapCreatingStreams(t *testing.T,
	perspective protocol.Perspective,
	firstIncomingBidiStream protocol.StreamID,
	firstOutgoingBidiStream protocol.StreamID,
	firstIncomingUniStream protocol.StreamID,
	firstOutgoingUniStream protocol.StreamID,
) {
	mockCtrl := gomock.NewController(t)
	mockSender := NewMockStreamSender(mockCtrl)
	m := newStreamsMap(
		context.Background(),
		mockSender,
		func(wire.Frame) {},
		func(protocol.StreamID) flowcontrol.StreamFlowController {
			fc := mocks.NewMockStreamFlowController(mockCtrl)
			fc.EXPECT().UpdateHighestReceived(gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes()
			return fc
		},
		1,
		1,
		perspective,
	)
	m.HandleTransportParameters(&wire.TransportParameters{
		MaxBidiStreamNum: protocol.MaxStreamCount,
		MaxUniStreamNum:  protocol.MaxStreamCount,
	})

	// opening streams
	str1, err := m.OpenStream()
	require.NoError(t, err)
	str2, err := m.OpenStream()
	require.NoError(t, err)
	ustr1, err := m.OpenUniStream()
	require.NoError(t, err)
	ustr2, err := m.OpenUniStream()
	require.NoError(t, err)

	assert.Equal(t, str1.StreamID(), firstOutgoingBidiStream)
	assert.Equal(t, str2.StreamID(), firstOutgoingBidiStream+4)
	assert.Equal(t, ustr1.StreamID(), firstOutgoingUniStream)
	assert.Equal(t, ustr2.StreamID(), firstOutgoingUniStream+4)

	// accepting streams is triggered by receiving a frame referencing this stream
	require.NoError(t, m.HandleStreamFrame(&wire.StreamFrame{StreamID: firstIncomingBidiStream}, monotime.Now()))
	require.NoError(t, m.HandleStreamFrame(&wire.StreamFrame{StreamID: firstIncomingUniStream}, monotime.Now()))

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	str, err := m.AcceptStream(ctx)
	require.NoError(t, err)
	ustr, err := m.AcceptUniStream(ctx)
	require.NoError(t, err)

	assert.Equal(t, str.StreamID(), firstIncomingBidiStream)
	assert.Equal(t, ustr.StreamID(), firstIncomingUniStream)
}

func TestStreamsMapDeletingStreams(t *testing.T) {
	t.Run("client", func(t *testing.T) {
		testStreamsMapDeletingStreams(t, protocol.PerspectiveClient,
			protocol.FirstIncomingBidiStreamClient,
			protocol.FirstOutgoingBidiStreamClient,
			protocol.FirstIncomingUniStreamClient,
			protocol.FirstOutgoingUniStreamClient,
		)
	})
	t.Run("server", func(t *testing.T) {
		testStreamsMapDeletingStreams(t, protocol.PerspectiveServer,
			protocol.FirstIncomingBidiStreamServer,
			protocol.FirstOutgoingBidiStreamServer,
			protocol.FirstIncomingUniStreamServer,
			protocol.FirstOutgoingUniStreamServer,
		)
	})
}

func testStreamsMapDeletingStreams(t *testing.T,
	perspective protocol.Perspective,
	firstIncomingBidiStream protocol.StreamID,
	firstOutgoingBidiStream protocol.StreamID,
	firstIncomingUniStream protocol.StreamID,
	firstOutgoingUniStream protocol.StreamID,
) {
	mockCtrl := gomock.NewController(t)
	mockSender := NewMockStreamSender(mockCtrl)
	var frameQueue []wire.Frame
	m := newStreamsMap(
		context.Background(),
		mockSender,
		func(frame wire.Frame) { frameQueue = append(frameQueue, frame) },
		func(protocol.StreamID) flowcontrol.StreamFlowController {
			fc := mocks.NewMockStreamFlowController(mockCtrl)
			fc.EXPECT().UpdateHighestReceived(gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes()
			return fc
		},
		100,
		100,
		perspective,
	)
	m.HandleTransportParameters(&wire.TransportParameters{
		MaxBidiStreamNum: 10,
		MaxUniStreamNum:  10,
	})

	_, err := m.OpenStream()
	require.NoError(t, err)
	require.NoError(t, m.DeleteStream(firstOutgoingBidiStream))
	err = m.DeleteStream(firstOutgoingBidiStream + 400)
	require.ErrorIs(t, err, &qerr.TransportError{ErrorCode: qerr.StreamStateError})
	require.ErrorContains(t, err, fmt.Sprintf("tried to delete unknown outgoing stream %d", firstOutgoingBidiStream+400))

	_, err = m.OpenUniStream()
	require.NoError(t, err)
	require.NoError(t, m.DeleteStream(firstOutgoingUniStream))
	err = m.DeleteStream(firstOutgoingUniStream + 400)
	require.ErrorIs(t, err, &qerr.TransportError{ErrorCode: qerr.StreamStateError})
	require.ErrorContains(t, err, fmt.Sprintf("tried to delete unknown outgoing stream %d", firstOutgoingUniStream+400))

	require.Empty(t, frameQueue)
	// deleting incoming bidirectional streams
	require.NoError(t, m.HandleStreamFrame(&wire.StreamFrame{StreamID: firstIncomingBidiStream}, monotime.Now()))
	require.NoError(t, m.DeleteStream(firstIncomingBidiStream))
	err = m.DeleteStream(firstIncomingBidiStream + 400)
	require.ErrorIs(t, err, &qerr.TransportError{ErrorCode: qerr.StreamStateError})
	require.ErrorContains(t, err, fmt.Sprintf("tried to delete unknown incoming stream %d", firstIncomingBidiStream+400))

	// the MAX_STREAMS frame is only queued once the stream is accepted
	require.Empty(t, frameQueue)
	_, err = m.AcceptStream(context.Background())
	require.NoError(t, err)

	require.Equal(t, frameQueue, []wire.Frame{
		&wire.MaxStreamsFrame{
			Type:         protocol.StreamTypeBidi,
			MaxStreamNum: 101,
		},
	})
	frameQueue = frameQueue[:0]

	// deleting incoming unidirectional streams
	require.NoError(t, m.HandleStreamFrame(&wire.StreamFrame{StreamID: firstIncomingUniStream}, monotime.Now()))
	require.NoError(t, m.DeleteStream(firstIncomingUniStream))
	err = m.DeleteStream(firstIncomingUniStream + 400)
	require.ErrorIs(t, err, &qerr.TransportError{ErrorCode: qerr.StreamStateError})
	require.ErrorContains(t, err, fmt.Sprintf("tried to delete unknown incoming stream %d", firstIncomingUniStream+400))

	// the MAX_STREAMS frame is only queued once the stream is accepted
	require.Empty(t, frameQueue)
	_, err = m.AcceptUniStream(context.Background())
	require.NoError(t, err)

	require.Equal(t, frameQueue, []wire.Frame{
		&wire.MaxStreamsFrame{
			Type:         protocol.StreamTypeUni,
			MaxStreamNum: 101,
		},
	})
	frameQueue = frameQueue[:0]
}

func TestStreamsMapStreamLimits(t *testing.T) {
	t.Run("client", func(t *testing.T) {
		testStreamsMapStreamLimits(t, protocol.PerspectiveClient)
	})
	t.Run("server", func(t *testing.T) {
		testStreamsMapStreamLimits(t, protocol.PerspectiveServer)
	})
}

func testStreamsMapStreamLimits(t *testing.T, perspective protocol.Perspective) {
	mockCtrl := gomock.NewController(t)
	mockSender := NewMockStreamSender(mockCtrl)
	var frameQueue []wire.Frame
	m := newStreamsMap(
		context.Background(),
		mockSender,
		func(frame wire.Frame) { frameQueue = append(frameQueue, frame) },
		func(protocol.StreamID) flowcontrol.StreamFlowController {
			fc := mocks.NewMockStreamFlowController(mockCtrl)
			fc.EXPECT().UpdateSendWindow(gomock.Any()).AnyTimes()
			return fc
		},
		100,
		100,
		perspective,
	)

	// increase via transport parameters
	_, err := m.OpenStream()
	require.ErrorIs(t, err, &StreamLimitReachedError{})
	require.ErrorContains(t, err, "too many open streams")
	m.HandleTransportParameters(&wire.TransportParameters{MaxBidiStreamNum: 1})
	_, err = m.OpenStream()
	require.NoError(t, err)
	_, err = m.OpenStream()
	require.ErrorIs(t, err, &StreamLimitReachedError{})

	_, err = m.OpenUniStream()
	require.ErrorIs(t, err, &StreamLimitReachedError{})
	m.HandleTransportParameters(&wire.TransportParameters{MaxUniStreamNum: 1})
	_, err = m.OpenUniStream()
	require.NoError(t, err)
	_, err = m.OpenUniStream()
	require.ErrorIs(t, err, &StreamLimitReachedError{})

	// increase via MAX_STREAMS frames
	m.HandleMaxStreamsFrame(&wire.MaxStreamsFrame{
		Type:         protocol.StreamTypeBidi,
		MaxStreamNum: 2,
	})
	_, err = m.OpenStream()
	require.NoError(t, err)
	_, err = m.OpenStream()
	require.ErrorIs(t, err, &StreamLimitReachedError{})

	m.HandleMaxStreamsFrame(&wire.MaxStreamsFrame{
		Type:         protocol.StreamTypeUni,
		MaxStreamNum: 2,
	})
	_, err = m.OpenUniStream()
	require.NoError(t, err)
	_, err = m.OpenUniStream()
	require.ErrorIs(t, err, &StreamLimitReachedError{})

	// decrease via transport parameters
	m.HandleTransportParameters(&wire.TransportParameters{MaxBidiStreamNum: 0})
	_, err = m.OpenStream()
	require.ErrorIs(t, err, &StreamLimitReachedError{})
}

func TestStreamsMapHandleReceiveStreamFrames(t *testing.T) {
	for _, pers := range []protocol.Perspective{protocol.PerspectiveClient, protocol.PerspectiveServer} {
		t.Run(pers.String(), func(t *testing.T) {
			t.Run("STREAM frame", func(t *testing.T) {
				testStreamsMapHandleReceiveStreamFrames(t,
					pers,
					func(m *streamsMap, id protocol.StreamID) error {
						return m.HandleStreamFrame(&wire.StreamFrame{StreamID: id}, monotime.Now())
					},
				)
			})

			t.Run("STREAM_DATA_BLOCKED frame", func(t *testing.T) {
				testStreamsMapHandleReceiveStreamFrames(t,
					pers,
					func(m *streamsMap, id protocol.StreamID) error {
						return m.HandleStreamDataBlockedFrame(&wire.StreamDataBlockedFrame{StreamID: id})
					},
				)
			})

			t.Run("RESET_STREAM frame", func(t *testing.T) {
				testStreamsMapHandleReceiveStreamFrames(t,
					pers,
					func(m *streamsMap, id protocol.StreamID) error {
						return m.HandleResetStreamFrame(&wire.ResetStreamFrame{StreamID: id}, monotime.Now())
					},
				)
			})
		})
	}
}

func testStreamsMapHandleReceiveStreamFrames(t *testing.T, pers protocol.Perspective, handleFrame func(*streamsMap, protocol.StreamID) error) {
	mockCtrl := gomock.NewController(t)
	mockSender := NewMockStreamSender(mockCtrl)
	var streamsCreated []protocol.StreamID
	m := newStreamsMap(
		context.Background(),
		mockSender,
		func(frame wire.Frame) {},
		func(id protocol.StreamID) flowcontrol.StreamFlowController {
			streamsCreated = append(streamsCreated, id)
			fc := mocks.NewMockStreamFlowController(mockCtrl)
			fc.EXPECT().UpdateHighestReceived(gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes()
			fc.EXPECT().Abandon().AnyTimes()
			return fc
		},
		100,
		100,
		pers,
	)
	m.HandleMaxStreamsFrame(&wire.MaxStreamsFrame{Type: protocol.StreamTypeBidi, MaxStreamNum: protocol.MaxStreamCount})
	m.HandleMaxStreamsFrame(&wire.MaxStreamsFrame{Type: protocol.StreamTypeUni, MaxStreamNum: protocol.MaxStreamCount})

	var firstOutgoingUniStream, firstOutgoingBidiStream, firstIncomingUniStream, firstIncomingBidiStream protocol.StreamID
	if pers == protocol.PerspectiveClient {
		firstOutgoingBidiStream = protocol.FirstOutgoingBidiStreamClient
		firstOutgoingUniStream = protocol.FirstOutgoingUniStreamClient
		firstIncomingUniStream = protocol.FirstIncomingUniStreamClient
		firstIncomingBidiStream = protocol.FirstIncomingBidiStreamClient
	} else {
		firstOutgoingBidiStream = protocol.FirstOutgoingBidiStreamServer
		firstOutgoingUniStream = protocol.FirstOutgoingUniStreamServer
		firstIncomingUniStream = protocol.FirstIncomingUniStreamServer
		firstIncomingBidiStream = protocol.FirstIncomingBidiStreamServer
	}

	// 1. The peer can't open a unidirectional send stream...
	err := handleFrame(m, firstOutgoingUniStream)
	require.ErrorIs(t, err, &qerr.TransportError{ErrorCode: qerr.StreamStateError})
	require.ErrorContains(t, err, fmt.Sprintf("invalid frame for receive stream %d", firstOutgoingUniStream))
	require.Empty(t, streamsCreated)
	// ... and a STREAM frame for a unidirectional send stream is invalid even if the stream is open.
	_, err = m.OpenUniStream()
	require.NoError(t, err)
	err = handleFrame(m, firstOutgoingUniStream)
	require.ErrorIs(t, err, &qerr.TransportError{ErrorCode: qerr.StreamStateError})
	require.ErrorContains(t, err, fmt.Sprintf("invalid frame for receive stream %d", firstOutgoingUniStream))
	streamsCreated = streamsCreated[:0]

	// 2. The peer can't open a bidirectional stream initiated by us...
	err = handleFrame(m, firstOutgoingBidiStream)
	require.ErrorIs(t, err, &qerr.TransportError{ErrorCode: qerr.StreamStateError})
	require.ErrorContains(t, err, fmt.Sprintf("peer attempted to open stream %d", firstOutgoingBidiStream))
	require.Empty(t, streamsCreated)
	// ... but it's valid once we have opened the stream.
	_, err = m.OpenStream()
	require.NoError(t, err)
	require.NoError(t, handleFrame(m, firstOutgoingBidiStream))
	streamsCreated = streamsCreated[:0]
	// Delayed frames for deleted streams are absorbed.
	require.NoError(t, m.DeleteStream(firstOutgoingBidiStream))
	require.NoError(t, handleFrame(m, firstOutgoingBidiStream))
	require.Empty(t, streamsCreated)

	// 3. The peer can send STREAM frames for unidirectional receive streams,
	// as long as they're below the stream limit.
	require.ErrorIs(t,
		handleFrame(m, firstIncomingUniStream+400),
		&qerr.TransportError{ErrorCode: qerr.StreamLimitError},
	)
	require.Empty(t, streamsCreated)
	require.NoError(t, handleFrame(m, firstIncomingUniStream))
	require.Equal(t, streamsCreated, []protocol.StreamID{firstIncomingUniStream})
	streamsCreated = streamsCreated[:0]
	// Delayed frames for deleted streams are absorbed.
	require.NoError(t, m.DeleteStream(firstIncomingUniStream))
	require.NoError(t, handleFrame(m, firstIncomingUniStream))
	require.Empty(t, streamsCreated)

	// 4. The peer can send STREAM frames for bidirectional receive streams,
	// as long as they're below the stream limit.
	require.ErrorIs(t,
		handleFrame(m, firstIncomingBidiStream+400),
		&qerr.TransportError{ErrorCode: qerr.StreamLimitError},
	)
	require.Empty(t, streamsCreated)
	require.NoError(t, handleFrame(m, firstIncomingBidiStream))
	require.Equal(t, streamsCreated, []protocol.StreamID{firstIncomingBidiStream})
}

func TestStreamsMapHandleSendStreamFrames(t *testing.T) {
	for _, pers := range []protocol.Perspective{protocol.PerspectiveClient, protocol.PerspectiveServer} {
		t.Run(pers.String(), func(t *testing.T) {
			t.Run("STOP_SENDING frame", func(t *testing.T) {
				testStreamsMapHandleSendStreamFrames(t,
					pers,
					func(m *streamsMap, id protocol.StreamID) error {
						return m.HandleStopSendingFrame(&wire.StopSendingFrame{StreamID: id})
					},
				)
			})

			t.Run("MAX_STREAM_DATA frame", func(t *testing.T) {
				testStreamsMapHandleSendStreamFrames(t,
					pers,
					func(m *streamsMap, id protocol.StreamID) error {
						return m.HandleMaxStreamDataFrame(&wire.MaxStreamDataFrame{StreamID: id, MaximumStreamData: 1000})
					},
				)
			})
		})
	}
}

func testStreamsMapHandleSendStreamFrames(t *testing.T, pers protocol.Perspective, handleFrame func(m *streamsMap, id protocol.StreamID) error) {
	mockCtrl := gomock.NewController(t)
	mockSender := NewMockStreamSender(mockCtrl)
	mockSender.EXPECT().onHasStreamControlFrame(gomock.Any(), gomock.Any()).AnyTimes()
	var streamsCreated []protocol.StreamID
	m := newStreamsMap(
		context.Background(),
		mockSender,
		func(frame wire.Frame) {},
		func(id protocol.StreamID) flowcontrol.StreamFlowController {
			streamsCreated = append(streamsCreated, id)
			fc := mocks.NewMockStreamFlowController(mockCtrl)
			fc.EXPECT().UpdateSendWindow(gomock.Any()).AnyTimes()
			return fc
		},
		100,
		100,
		pers,
	)
	m.HandleMaxStreamsFrame(&wire.MaxStreamsFrame{Type: protocol.StreamTypeBidi, MaxStreamNum: protocol.MaxStreamCount})
	m.HandleMaxStreamsFrame(&wire.MaxStreamsFrame{Type: protocol.StreamTypeUni, MaxStreamNum: protocol.MaxStreamCount})

	var firstOutgoingUniStream, firstOutgoingBidiStream, firstIncomingUniStream, firstIncomingBidiStream protocol.StreamID
	if pers == protocol.PerspectiveClient {
		firstOutgoingBidiStream = protocol.FirstOutgoingBidiStreamClient
		firstOutgoingUniStream = protocol.FirstOutgoingUniStreamClient
		firstIncomingUniStream = protocol.FirstIncomingUniStreamClient
		firstIncomingBidiStream = protocol.FirstIncomingBidiStreamClient
	} else {
		firstOutgoingBidiStream = protocol.FirstOutgoingBidiStreamServer
		firstOutgoingUniStream = protocol.FirstOutgoingUniStreamServer
		firstIncomingUniStream = protocol.FirstIncomingUniStreamServer
		firstIncomingBidiStream = protocol.FirstIncomingBidiStreamServer
	}

	// 1. The peer can't open a unidirectional send stream...
	err := handleFrame(m, firstOutgoingUniStream)
	require.ErrorIs(t, err, &qerr.TransportError{ErrorCode: qerr.StreamStateError})
	require.ErrorContains(t, err, fmt.Sprintf("peer attempted to open stream %d", firstOutgoingUniStream))
	require.Empty(t, streamsCreated)
	// ... but once we have opened the stream, it's valid.
	_, err = m.OpenUniStream()
	require.NoError(t, err)
	require.NoError(t, handleFrame(m, firstOutgoingUniStream))
	streamsCreated = streamsCreated[:0]
	// Delayed frames for deleted streams are absorbed.
	require.NoError(t, m.DeleteStream(firstOutgoingUniStream))
	require.NoError(t, handleFrame(m, firstOutgoingUniStream))
	require.Empty(t, streamsCreated)

	// 2. The peer can't open a bidirectional stream initiated by us...
	err = handleFrame(m, firstOutgoingBidiStream)
	require.ErrorIs(t, err, &qerr.TransportError{ErrorCode: qerr.StreamStateError})
	require.ErrorContains(t, err, fmt.Sprintf("peer attempted to open stream %d", firstOutgoingBidiStream))
	require.Empty(t, streamsCreated)
	// ... but once we have opened the stream, it's valid.
	_, err = m.OpenStream()
	require.NoError(t, err)
	require.NoError(t, handleFrame(m, firstOutgoingBidiStream))
	streamsCreated = streamsCreated[:0]
	// Delayed frames for deleted streams are absorbed.
	require.NoError(t, m.DeleteStream(firstOutgoingBidiStream))
	require.NoError(t, handleFrame(m, firstOutgoingBidiStream))
	require.Empty(t, streamsCreated)

	// 3. The peer can't send STOP_SENDING frames for unidirectional send streams
	err = handleFrame(m, firstIncomingUniStream)
	require.ErrorIs(t, err, &qerr.TransportError{ErrorCode: qerr.StreamStateError})
	require.ErrorContains(t, err, fmt.Sprintf("invalid frame for send stream %d", firstIncomingUniStream))
	require.Empty(t, streamsCreated)

	// 4. The peer can send STOP_SENDING frames for bidirectional receive streams iniated by itself,
	// as long as they're below the stream limit.
	require.ErrorIs(t,
		handleFrame(m, firstIncomingBidiStream+400),
		&qerr.TransportError{ErrorCode: qerr.StreamLimitError},
	)
	require.Empty(t, streamsCreated)
	require.NoError(t, handleFrame(m, firstIncomingBidiStream))
	require.Equal(t, streamsCreated, []protocol.StreamID{firstIncomingBidiStream})
	streamsCreated = streamsCreated[:0]
	// Delayed frames for deleted streams are absorbed.
	require.NoError(t, m.DeleteStream(firstIncomingBidiStream))
	require.NoError(t, handleFrame(m, firstIncomingBidiStream))
	require.Empty(t, streamsCreated)
}

func TestStreamsMapClosing(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	mockSender := NewMockStreamSender(mockCtrl)
	m := newStreamsMap(
		context.Background(),
		mockSender,
		func(wire.Frame) {},
		func(protocol.StreamID) flowcontrol.StreamFlowController {
			return mocks.NewMockStreamFlowController(mockCtrl)
		},
		1,
		1,
		protocol.PerspectiveClient,
	)
	m.CloseWithError(assert.AnError)
	_, err := m.OpenStream()
	require.ErrorIs(t, err, assert.AnError)
	_, err = m.OpenUniStream()
	require.ErrorIs(t, err, assert.AnError)
	_, err = m.AcceptStream(context.Background())
	require.ErrorIs(t, err, assert.AnError)
	_, err = m.AcceptUniStream(context.Background())
	require.ErrorIs(t, err, assert.AnError)
}

func TestStreamsMap0RTT(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	mockSender := NewMockStreamSender(mockCtrl)
	fcBidi := mocks.NewMockStreamFlowController(mockCtrl)
	fcUni := mocks.NewMockStreamFlowController(mockCtrl)
	fcs := []flowcontrol.StreamFlowController{fcBidi, fcUni}
	m := newStreamsMap(
		context.Background(),
		mockSender,
		func(wire.Frame) {},
		func(protocol.StreamID) flowcontrol.StreamFlowController {
			fc := fcs[0]
			fcs = fcs[1:]
			return fc
		},
		1,
		1,
		protocol.PerspectiveClient,
	)
	// restored transport parameters
	m.HandleTransportParameters(&wire.TransportParameters{
		MaxBidiStreamNum: 1,
		MaxUniStreamNum:  1,
	})
	_, err := m.OpenStream()
	require.NoError(t, err)
	_, err = m.OpenUniStream()
	require.NoError(t, err)

	fcBidi.EXPECT().UpdateSendWindow(protocol.ByteCount(1234))
	fcUni.EXPECT().UpdateSendWindow(protocol.ByteCount(4321))
	// new transport parameters
	m.HandleTransportParameters(&wire.TransportParameters{
		MaxBidiStreamNum:               1000,
		InitialMaxStreamDataBidiRemote: 1234,
		MaxUniStreamNum:                1000,
		InitialMaxStreamDataUni:        4321,
	})
}

func TestStreamsMap0RTTRejection(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	mockSender := NewMockStreamSender(mockCtrl)
	m := newStreamsMap(
		context.Background(),
		mockSender,
		func(wire.Frame) {},
		func(protocol.StreamID) flowcontrol.StreamFlowController {
			fc := mocks.NewMockStreamFlowController(mockCtrl)
			fc.EXPECT().UpdateHighestReceived(gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes()
			return fc
		},
		1,
		1,
		protocol.PerspectiveClient,
	)

	m.ResetFor0RTT()
	_, err := m.OpenStream()
	require.ErrorIs(t, err, Err0RTTRejected)
	_, err = m.OpenUniStream()
	require.ErrorIs(t, err, Err0RTTRejected)
	_, err = m.AcceptStream(context.Background())
	require.ErrorIs(t, err, Err0RTTRejected)
	_, err = m.AcceptUniStream(context.Background())
	require.ErrorIs(t, err, Err0RTTRejected)

	// make sure that we can still get new streams, as the server might be sending us data
	require.NoError(t, m.HandleStreamFrame(&wire.StreamFrame{StreamID: 3}, monotime.Now()))

	// now switch to using the new streams map
	m.UseResetMaps()
	_, err = m.OpenStream()
	require.Error(t, err)
	require.ErrorIs(t, err, &StreamLimitReachedError{})
}
