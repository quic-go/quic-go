package quic

import (
	"context"
	"errors"
	"fmt"
	"net"

	"github.com/golang/mock/gomock"

	"github.com/lucas-clemente/quic-go/internal/flowcontrol"
	"github.com/lucas-clemente/quic-go/internal/mocks"
	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/qerr"
	"github.com/lucas-clemente/quic-go/internal/wire"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func (e streamError) TestError() error {
	nums := make([]interface{}, len(e.nums))
	for i, num := range e.nums {
		nums[i] = num
	}
	return fmt.Errorf(e.message, nums...)
}

type streamMapping struct {
	firstIncomingBidiStream protocol.StreamID
	firstIncomingUniStream  protocol.StreamID
	firstOutgoingBidiStream protocol.StreamID
	firstOutgoingUniStream  protocol.StreamID
}

func expectTooManyStreamsError(err error) {
	ExpectWithOffset(1, err).To(HaveOccurred())
	ExpectWithOffset(1, err.Error()).To(Equal(errTooManyOpenStreams.Error()))
	nerr, ok := err.(net.Error)
	ExpectWithOffset(1, ok).To(BeTrue())
	ExpectWithOffset(1, nerr.Timeout()).To(BeFalse())
}

var _ = Describe("Streams Map", func() {
	newFlowController := func(protocol.StreamID) flowcontrol.StreamFlowController {
		return mocks.NewMockStreamFlowController(mockCtrl)
	}

	serverStreamMapping := streamMapping{
		firstIncomingBidiStream: 0,
		firstOutgoingBidiStream: 1,
		firstIncomingUniStream:  2,
		firstOutgoingUniStream:  3,
	}
	clientStreamMapping := streamMapping{
		firstIncomingBidiStream: 1,
		firstOutgoingBidiStream: 0,
		firstIncomingUniStream:  3,
		firstOutgoingUniStream:  2,
	}

	for _, p := range []protocol.Perspective{protocol.PerspectiveServer, protocol.PerspectiveClient} {
		perspective := p
		var ids streamMapping
		if perspective == protocol.PerspectiveClient {
			ids = clientStreamMapping
		} else {
			ids = serverStreamMapping
		}

		Context(perspective.String(), func() {
			var (
				m          *streamsMap
				mockSender *MockStreamSender
			)

			const (
				MaxBidiStreamNum = 111
				MaxUniStreamNum  = 222
			)

			allowUnlimitedStreams := func() {
				m.UpdateLimits(&wire.TransportParameters{
					MaxBidiStreamNum: protocol.MaxStreamCount,
					MaxUniStreamNum:  protocol.MaxStreamCount,
				})
			}

			BeforeEach(func() {
				mockSender = NewMockStreamSender(mockCtrl)
				m = newStreamsMap(mockSender, newFlowController, MaxBidiStreamNum, MaxUniStreamNum, perspective, protocol.VersionWhatever).(*streamsMap)
			})

			Context("opening", func() {
				It("opens bidirectional streams", func() {
					allowUnlimitedStreams()
					str, err := m.OpenStream()
					Expect(err).ToNot(HaveOccurred())
					Expect(str).To(BeAssignableToTypeOf(&stream{}))
					Expect(str.StreamID()).To(Equal(ids.firstOutgoingBidiStream))
					str, err = m.OpenStream()
					Expect(err).ToNot(HaveOccurred())
					Expect(str).To(BeAssignableToTypeOf(&stream{}))
					Expect(str.StreamID()).To(Equal(ids.firstOutgoingBidiStream + 4))
				})

				It("opens unidirectional streams", func() {
					allowUnlimitedStreams()
					str, err := m.OpenUniStream()
					Expect(err).ToNot(HaveOccurred())
					Expect(str).To(BeAssignableToTypeOf(&sendStream{}))
					Expect(str.StreamID()).To(Equal(ids.firstOutgoingUniStream))
					str, err = m.OpenUniStream()
					Expect(err).ToNot(HaveOccurred())
					Expect(str).To(BeAssignableToTypeOf(&sendStream{}))
					Expect(str.StreamID()).To(Equal(ids.firstOutgoingUniStream + 4))
				})
			})

			Context("accepting", func() {
				It("accepts bidirectional streams", func() {
					_, err := m.GetOrOpenReceiveStream(ids.firstIncomingBidiStream)
					Expect(err).ToNot(HaveOccurred())
					str, err := m.AcceptStream(context.Background())
					Expect(err).ToNot(HaveOccurred())
					Expect(str).To(BeAssignableToTypeOf(&stream{}))
					Expect(str.StreamID()).To(Equal(ids.firstIncomingBidiStream))
				})

				It("accepts unidirectional streams", func() {
					_, err := m.GetOrOpenReceiveStream(ids.firstIncomingUniStream)
					Expect(err).ToNot(HaveOccurred())
					str, err := m.AcceptUniStream(context.Background())
					Expect(err).ToNot(HaveOccurred())
					Expect(str).To(BeAssignableToTypeOf(&receiveStream{}))
					Expect(str.StreamID()).To(Equal(ids.firstIncomingUniStream))
				})
			})

			Context("deleting", func() {
				BeforeEach(func() {
					mockSender.EXPECT().queueControlFrame(gomock.Any()).AnyTimes()
					allowUnlimitedStreams()
				})

				It("deletes outgoing bidirectional streams", func() {
					id := ids.firstOutgoingBidiStream
					str, err := m.OpenStream()
					Expect(err).ToNot(HaveOccurred())
					Expect(str.StreamID()).To(Equal(id))
					Expect(m.DeleteStream(id)).To(Succeed())
					dstr, err := m.GetOrOpenSendStream(id)
					Expect(err).ToNot(HaveOccurred())
					Expect(dstr).To(BeNil())
				})

				It("deletes incoming bidirectional streams", func() {
					id := ids.firstIncomingBidiStream
					str, err := m.GetOrOpenReceiveStream(id)
					Expect(err).ToNot(HaveOccurred())
					Expect(str.StreamID()).To(Equal(id))
					Expect(m.DeleteStream(id)).To(Succeed())
					dstr, err := m.GetOrOpenReceiveStream(id)
					Expect(err).ToNot(HaveOccurred())
					Expect(dstr).To(BeNil())
				})

				It("accepts bidirectional streams after they have been deleted", func() {
					id := ids.firstIncomingBidiStream
					_, err := m.GetOrOpenReceiveStream(id)
					Expect(err).ToNot(HaveOccurred())
					Expect(m.DeleteStream(id)).To(Succeed())
					str, err := m.AcceptStream(context.Background())
					Expect(err).ToNot(HaveOccurred())
					Expect(str).ToNot(BeNil())
					Expect(str.StreamID()).To(Equal(id))
				})

				It("deletes outgoing unidirectional streams", func() {
					id := ids.firstOutgoingUniStream
					str, err := m.OpenUniStream()
					Expect(err).ToNot(HaveOccurred())
					Expect(str.StreamID()).To(Equal(id))
					Expect(m.DeleteStream(id)).To(Succeed())
					dstr, err := m.GetOrOpenSendStream(id)
					Expect(err).ToNot(HaveOccurred())
					Expect(dstr).To(BeNil())
				})

				It("deletes incoming unidirectional streams", func() {
					id := ids.firstIncomingUniStream
					str, err := m.GetOrOpenReceiveStream(id)
					Expect(err).ToNot(HaveOccurred())
					Expect(str.StreamID()).To(Equal(id))
					Expect(m.DeleteStream(id)).To(Succeed())
					dstr, err := m.GetOrOpenReceiveStream(id)
					Expect(err).ToNot(HaveOccurred())
					Expect(dstr).To(BeNil())
				})

				It("accepts unirectional streams after they have been deleted", func() {
					id := ids.firstIncomingUniStream
					_, err := m.GetOrOpenReceiveStream(id)
					Expect(err).ToNot(HaveOccurred())
					Expect(m.DeleteStream(id)).To(Succeed())
					str, err := m.AcceptUniStream(context.Background())
					Expect(err).ToNot(HaveOccurred())
					Expect(str).ToNot(BeNil())
					Expect(str.StreamID()).To(Equal(id))
				})

				It("errors when deleting unknown incoming unidirectional streams", func() {
					id := ids.firstIncomingUniStream + 4
					Expect(m.DeleteStream(id)).To(MatchError(fmt.Sprintf("tried to delete unknown incoming stream %d", id)))
				})

				It("errors when deleting unknown outgoing unidirectional streams", func() {
					id := ids.firstOutgoingUniStream + 4
					Expect(m.DeleteStream(id)).To(MatchError(fmt.Sprintf("tried to delete unknown outgoing stream %d", id)))
				})

				It("errors when deleting unknown incoming bidirectional streams", func() {
					id := ids.firstIncomingBidiStream + 4
					Expect(m.DeleteStream(id)).To(MatchError(fmt.Sprintf("tried to delete unknown incoming stream %d", id)))
				})

				It("errors when deleting unknown outgoing bidirectional streams", func() {
					id := ids.firstOutgoingBidiStream + 4
					Expect(m.DeleteStream(id)).To(MatchError(fmt.Sprintf("tried to delete unknown outgoing stream %d", id)))
				})
			})

			Context("getting streams", func() {
				BeforeEach(func() {
					allowUnlimitedStreams()
				})

				Context("send streams", func() {
					It("gets an outgoing bidirectional stream", func() {
						// need to open the stream ourselves first
						// the peer is not allowed to create a stream initiated by us
						_, err := m.OpenStream()
						Expect(err).ToNot(HaveOccurred())
						str, err := m.GetOrOpenSendStream(ids.firstOutgoingBidiStream)
						Expect(err).ToNot(HaveOccurred())
						Expect(str.StreamID()).To(Equal(ids.firstOutgoingBidiStream))
					})

					It("errors when the peer tries to open a higher outgoing bidirectional stream", func() {
						id := ids.firstOutgoingBidiStream + 5*4
						_, err := m.GetOrOpenSendStream(id)
						Expect(err).To(MatchError(&qerr.TransportError{
							ErrorCode:    qerr.StreamStateError,
							ErrorMessage: fmt.Sprintf("peer attempted to open stream %d", id),
						}))
					})

					It("gets an outgoing unidirectional stream", func() {
						// need to open the stream ourselves first
						// the peer is not allowed to create a stream initiated by us
						_, err := m.OpenUniStream()
						Expect(err).ToNot(HaveOccurred())
						str, err := m.GetOrOpenSendStream(ids.firstOutgoingUniStream)
						Expect(err).ToNot(HaveOccurred())
						Expect(str.StreamID()).To(Equal(ids.firstOutgoingUniStream))
					})

					It("errors when the peer tries to open a higher outgoing bidirectional stream", func() {
						id := ids.firstOutgoingUniStream + 5*4
						_, err := m.GetOrOpenSendStream(id)
						Expect(err).To(MatchError(&qerr.TransportError{
							ErrorCode:    qerr.StreamStateError,
							ErrorMessage: fmt.Sprintf("peer attempted to open stream %d", id),
						}))
					})

					It("gets an incoming bidirectional stream", func() {
						id := ids.firstIncomingBidiStream + 4*7
						str, err := m.GetOrOpenSendStream(id)
						Expect(err).ToNot(HaveOccurred())
						Expect(str.StreamID()).To(Equal(id))
					})

					It("errors when trying to get an incoming unidirectional stream", func() {
						id := ids.firstIncomingUniStream
						_, err := m.GetOrOpenSendStream(id)
						Expect(err).To(MatchError(&qerr.TransportError{
							ErrorCode:    qerr.StreamStateError,
							ErrorMessage: fmt.Sprintf("peer attempted to open send stream %d", id),
						}))
					})
				})

				Context("receive streams", func() {
					It("gets an outgoing bidirectional stream", func() {
						// need to open the stream ourselves first
						// the peer is not allowed to create a stream initiated by us
						_, err := m.OpenStream()
						Expect(err).ToNot(HaveOccurred())
						str, err := m.GetOrOpenReceiveStream(ids.firstOutgoingBidiStream)
						Expect(err).ToNot(HaveOccurred())
						Expect(str.StreamID()).To(Equal(ids.firstOutgoingBidiStream))
					})

					It("errors when the peer tries to open a higher outgoing bidirectional stream", func() {
						id := ids.firstOutgoingBidiStream + 5*4
						_, err := m.GetOrOpenReceiveStream(id)
						Expect(err).To(MatchError(&qerr.TransportError{
							ErrorCode:    qerr.StreamStateError,
							ErrorMessage: fmt.Sprintf("peer attempted to open stream %d", id),
						}))
					})

					It("gets an incoming bidirectional stream", func() {
						id := ids.firstIncomingBidiStream + 4*7
						str, err := m.GetOrOpenReceiveStream(id)
						Expect(err).ToNot(HaveOccurred())
						Expect(str.StreamID()).To(Equal(id))
					})

					It("gets an incoming unidirectional stream", func() {
						id := ids.firstIncomingUniStream + 4*10
						str, err := m.GetOrOpenReceiveStream(id)
						Expect(err).ToNot(HaveOccurred())
						Expect(str.StreamID()).To(Equal(id))
					})

					It("errors when trying to get an outgoing unidirectional stream", func() {
						id := ids.firstOutgoingUniStream
						_, err := m.GetOrOpenReceiveStream(id)
						Expect(err).To(MatchError(&qerr.TransportError{
							ErrorCode:    qerr.StreamStateError,
							ErrorMessage: fmt.Sprintf("peer attempted to open receive stream %d", id),
						}))
					})
				})
			})

			It("processes the parameter for outgoing streams", func() {
				mockSender.EXPECT().queueControlFrame(gomock.Any())
				_, err := m.OpenStream()
				expectTooManyStreamsError(err)
				m.UpdateLimits(&wire.TransportParameters{
					MaxBidiStreamNum: 5,
					MaxUniStreamNum:  8,
				})

				mockSender.EXPECT().queueControlFrame(gomock.Any()).Times(2)
				// test we can only 5 bidirectional streams
				for i := 0; i < 5; i++ {
					str, err := m.OpenStream()
					Expect(err).ToNot(HaveOccurred())
					Expect(str.StreamID()).To(Equal(ids.firstOutgoingBidiStream + protocol.StreamID(4*i)))
				}
				_, err = m.OpenStream()
				expectTooManyStreamsError(err)
				// test we can only 8 unidirectional streams
				for i := 0; i < 8; i++ {
					str, err := m.OpenUniStream()
					Expect(err).ToNot(HaveOccurred())
					Expect(str.StreamID()).To(Equal(ids.firstOutgoingUniStream + protocol.StreamID(4*i)))
				}
				_, err = m.OpenUniStream()
				expectTooManyStreamsError(err)
			})

			if perspective == protocol.PerspectiveClient {
				It("applies parameters to existing streams (needed for 0-RTT)", func() {
					m.UpdateLimits(&wire.TransportParameters{
						MaxBidiStreamNum: 1000,
						MaxUniStreamNum:  1000,
					})
					flowControllers := make(map[protocol.StreamID]*mocks.MockStreamFlowController)
					m.newFlowController = func(id protocol.StreamID) flowcontrol.StreamFlowController {
						fc := mocks.NewMockStreamFlowController(mockCtrl)
						flowControllers[id] = fc
						return fc
					}

					str, err := m.OpenStream()
					Expect(err).ToNot(HaveOccurred())
					unistr, err := m.OpenUniStream()
					Expect(err).ToNot(HaveOccurred())

					Expect(flowControllers).To(HaveKey(str.StreamID()))
					flowControllers[str.StreamID()].EXPECT().UpdateSendWindow(protocol.ByteCount(4321))
					Expect(flowControllers).To(HaveKey(unistr.StreamID()))
					flowControllers[unistr.StreamID()].EXPECT().UpdateSendWindow(protocol.ByteCount(1234))

					m.UpdateLimits(&wire.TransportParameters{
						MaxBidiStreamNum:               1000,
						InitialMaxStreamDataUni:        1234,
						MaxUniStreamNum:                1000,
						InitialMaxStreamDataBidiRemote: 4321,
					})
				})
			}

			Context("handling MAX_STREAMS frames", func() {
				BeforeEach(func() {
					mockSender.EXPECT().queueControlFrame(gomock.Any()).AnyTimes()
				})

				It("processes IDs for outgoing bidirectional streams", func() {
					_, err := m.OpenStream()
					expectTooManyStreamsError(err)
					m.HandleMaxStreamsFrame(&wire.MaxStreamsFrame{
						Type:         protocol.StreamTypeBidi,
						MaxStreamNum: 1,
					})
					str, err := m.OpenStream()
					Expect(err).ToNot(HaveOccurred())
					Expect(str.StreamID()).To(Equal(ids.firstOutgoingBidiStream))
					_, err = m.OpenStream()
					expectTooManyStreamsError(err)
				})

				It("processes IDs for outgoing unidirectional streams", func() {
					_, err := m.OpenUniStream()
					expectTooManyStreamsError(err)
					m.HandleMaxStreamsFrame(&wire.MaxStreamsFrame{
						Type:         protocol.StreamTypeUni,
						MaxStreamNum: 1,
					})
					str, err := m.OpenUniStream()
					Expect(err).ToNot(HaveOccurred())
					Expect(str.StreamID()).To(Equal(ids.firstOutgoingUniStream))
					_, err = m.OpenUniStream()
					expectTooManyStreamsError(err)
				})
			})

			Context("sending MAX_STREAMS frames", func() {
				It("sends a MAX_STREAMS frame for bidirectional streams", func() {
					_, err := m.GetOrOpenReceiveStream(ids.firstIncomingBidiStream)
					Expect(err).ToNot(HaveOccurred())
					_, err = m.AcceptStream(context.Background())
					Expect(err).ToNot(HaveOccurred())
					mockSender.EXPECT().queueControlFrame(&wire.MaxStreamsFrame{
						Type:         protocol.StreamTypeBidi,
						MaxStreamNum: MaxBidiStreamNum + 1,
					})
					Expect(m.DeleteStream(ids.firstIncomingBidiStream)).To(Succeed())
				})

				It("sends a MAX_STREAMS frame for unidirectional streams", func() {
					_, err := m.GetOrOpenReceiveStream(ids.firstIncomingUniStream)
					Expect(err).ToNot(HaveOccurred())
					_, err = m.AcceptUniStream(context.Background())
					Expect(err).ToNot(HaveOccurred())
					mockSender.EXPECT().queueControlFrame(&wire.MaxStreamsFrame{
						Type:         protocol.StreamTypeUni,
						MaxStreamNum: MaxUniStreamNum + 1,
					})
					Expect(m.DeleteStream(ids.firstIncomingUniStream)).To(Succeed())
				})
			})

			It("closes", func() {
				testErr := errors.New("test error")
				m.CloseWithError(testErr)
				_, err := m.OpenStream()
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(Equal(testErr.Error()))
				_, err = m.OpenUniStream()
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(Equal(testErr.Error()))
				_, err = m.AcceptStream(context.Background())
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(Equal(testErr.Error()))
				_, err = m.AcceptUniStream(context.Background())
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(Equal(testErr.Error()))
			})

			if perspective == protocol.PerspectiveClient {
				It("resets for 0-RTT", func() {
					mockSender.EXPECT().queueControlFrame(gomock.Any()).AnyTimes()
					m.ResetFor0RTT()
					// make sure that calls to open / accept streams fail
					_, err := m.OpenStream()
					Expect(err).To(MatchError(Err0RTTRejected))
					_, err = m.AcceptStream(context.Background())
					Expect(err).To(MatchError(Err0RTTRejected))
					// make sure that we can still get new streams, as the server might be sending us data
					str, err := m.GetOrOpenReceiveStream(3)
					Expect(err).ToNot(HaveOccurred())
					Expect(str).ToNot(BeNil())

					// now switch to using the new streams map
					m.UseResetMaps()
					_, err = m.OpenStream()
					Expect(err).To(HaveOccurred())
					Expect(err.Error()).To(ContainSubstring("too many open streams"))
				})
			}
		})
	}
})
