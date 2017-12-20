package quic

import (
	"errors"
	"io"
	"strconv"
	"time"

	"os"

	"github.com/lucas-clemente/quic-go/internal/mocks"
	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/wire"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/gbytes"
)

// in the tests for the stream deadlines we set a deadline
// and wait to make an assertion when Read / Write was unblocked
// on the CIs, the timing is a lot less precise, so scale every duration by this factor
func scaleDuration(t time.Duration) time.Duration {
	scaleFactor := 1
	if f, err := strconv.Atoi(os.Getenv("TIMESCALE_FACTOR")); err == nil { // parsing "" errors, so this works fine if the env is not set
		scaleFactor = f
	}
	Expect(scaleFactor).ToNot(BeZero())
	return time.Duration(scaleFactor) * t
}

var _ = Describe("Stream", func() {
	const streamID protocol.StreamID = 1337

	var (
		str                 *stream
		strWithTimeout      io.ReadWriter // str wrapped with gbytes.Timeout{Reader,Writer}
		onDataCalled        bool
		queuedControlFrames []wire.Frame
		mockFC              *mocks.MockStreamFlowController
	)

	onData := func() { onDataCalled = true }
	queueControlFrame := func(f wire.Frame) { queuedControlFrames = append(queuedControlFrames, f) }

	BeforeEach(func() {
		queuedControlFrames = queuedControlFrames[:0]
		onDataCalled = false
		mockFC = mocks.NewMockStreamFlowController(mockCtrl)
		str = newStream(streamID, onData, queueControlFrame, mockFC, protocol.VersionWhatever)

		timeout := scaleDuration(250 * time.Millisecond)
		strWithTimeout = struct {
			io.Reader
			io.Writer
		}{
			gbytes.TimeoutReader(str, timeout),
			gbytes.TimeoutWriter(str, timeout),
		}
	})

	It("gets stream id", func() {
		Expect(str.StreamID()).To(Equal(protocol.StreamID(1337)))
	})

	// need some stream cancelation tests here, since gQUIC doesn't cleanly separate the two stream halves
	Context("stream cancelations", func() {
		Context("for gQUIC", func() {
			BeforeEach(func() {
				str.version = versionGQUICFrames
				str.receiveStream.version = versionGQUICFrames
				str.sendStream.version = versionGQUICFrames
			})

			It("unblocks Write when receiving a RST_STREAM frame with non-zero error code", func() {
				mockFC.EXPECT().UpdateHighestReceived(protocol.ByteCount(6), true)
				str.writeOffset = 1000
				f := &wire.RstStreamFrame{
					StreamID:   streamID,
					ByteOffset: 6,
					ErrorCode:  123,
				}
				writeReturned := make(chan struct{})
				go func() {
					defer GinkgoRecover()
					_, err := strWithTimeout.Write([]byte("foobar"))
					Expect(err).To(MatchError("Stream 1337 was reset with error code 123"))
					Expect(err).To(BeAssignableToTypeOf(streamCanceledError{}))
					Expect(err.(streamCanceledError).Canceled()).To(BeTrue())
					Expect(err.(streamCanceledError).ErrorCode()).To(Equal(protocol.ApplicationErrorCode(123)))
					close(writeReturned)
				}()
				Consistently(writeReturned).ShouldNot(BeClosed())
				err := str.handleRstStreamFrame(f)
				Expect(err).ToNot(HaveOccurred())
				Expect(queuedControlFrames).To(Equal([]wire.Frame{
					&wire.RstStreamFrame{
						StreamID:   streamID,
						ByteOffset: 1000,
						ErrorCode:  errorCodeStoppingGQUIC,
					},
				}))
				Eventually(writeReturned).Should(BeClosed())
			})

			It("unblocks Write when receiving a RST_STREAM frame with error code 0", func() {
				mockFC.EXPECT().UpdateHighestReceived(protocol.ByteCount(6), true)
				str.writeOffset = 1000
				f := &wire.RstStreamFrame{
					StreamID:   streamID,
					ByteOffset: 6,
					ErrorCode:  0,
				}
				writeReturned := make(chan struct{})
				go func() {
					defer GinkgoRecover()
					_, err := strWithTimeout.Write([]byte("foobar"))
					Expect(err).To(MatchError("Stream 1337 was reset with error code 0"))
					Expect(err).To(BeAssignableToTypeOf(streamCanceledError{}))
					Expect(err.(streamCanceledError).Canceled()).To(BeTrue())
					Expect(err.(streamCanceledError).ErrorCode()).To(Equal(protocol.ApplicationErrorCode(0)))
					close(writeReturned)
				}()
				Consistently(writeReturned).ShouldNot(BeClosed())
				err := str.handleRstStreamFrame(f)
				Expect(err).ToNot(HaveOccurred())
				Expect(queuedControlFrames).To(Equal([]wire.Frame{
					&wire.RstStreamFrame{
						StreamID:   streamID,
						ByteOffset: 1000,
						ErrorCode:  errorCodeStoppingGQUIC,
					},
				}))
				Eventually(writeReturned).Should(BeClosed())
			})

			It("sends a RST_STREAM with error code 0, after the stream is closed", func() {
				str.version = versionGQUICFrames
				mockFC.EXPECT().SendWindowSize().Return(protocol.MaxByteCount).AnyTimes()
				mockFC.EXPECT().AddBytesSent(protocol.ByteCount(6))
				mockFC.EXPECT().IsNewlyBlocked()
				err := str.CancelRead(1234)
				Expect(err).ToNot(HaveOccurred())
				Expect(queuedControlFrames).To(BeEmpty()) // no RST_STREAM frame queued yet
				writeReturned := make(chan struct{})
				go func() {
					defer GinkgoRecover()
					_, err := strWithTimeout.Write([]byte("foobar"))
					Expect(err).ToNot(HaveOccurred())
					close(writeReturned)
				}()
				Eventually(func() *wire.StreamFrame { return str.popStreamFrame(1000) }).ShouldNot(BeNil())
				Eventually(writeReturned).Should(BeClosed())
				Expect(queuedControlFrames).To(BeEmpty()) // no RST_STREAM frame queued yet
				err = str.Close()
				Expect(err).ToNot(HaveOccurred())
				Expect(queuedControlFrames).To(Equal([]wire.Frame{
					&wire.RstStreamFrame{
						StreamID:   streamID,
						ByteOffset: 6,
						ErrorCode:  0,
					},
				}))
			})
		})

		Context("for IETF QUIC", func() {
			It("doesn't queue a RST_STREAM after closing the stream", func() { // this is what it does for gQUIC
				err := str.CancelRead(1234)
				Expect(err).ToNot(HaveOccurred())
				Expect(queuedControlFrames).To(HaveLen(1))
				Expect(queuedControlFrames[0]).To(BeAssignableToTypeOf(&wire.StopSendingFrame{}))
				Expect(str.Close()).To(Succeed())
				Expect(queuedControlFrames).To(HaveLen(1))
			})
		})
	})

	Context("deadlines", func() {
		It("sets a write deadline, when SetDeadline is called", func() {
			str.SetDeadline(time.Now().Add(-time.Second))
			n, err := strWithTimeout.Write([]byte("foobar"))
			Expect(err).To(MatchError(errDeadline))
			Expect(n).To(BeZero())
		})

		It("sets a read deadline, when SetDeadline is called", func() {
			mockFC.EXPECT().UpdateHighestReceived(protocol.ByteCount(6), false).AnyTimes()
			f := &wire.StreamFrame{Data: []byte("foobar")}
			err := str.handleStreamFrame(f)
			Expect(err).ToNot(HaveOccurred())
			str.SetDeadline(time.Now().Add(-time.Second))
			b := make([]byte, 6)
			n, err := strWithTimeout.Read(b)
			Expect(err).To(MatchError(errDeadline))
			Expect(n).To(BeZero())
		})
	})

	Context("saying if it is finished", func() {
		It("is finished when both the send and the receive side are finished", func() {
			str.receiveStream.closeForShutdown(errors.New("shutdown"))
			Expect(str.receiveStream.finished()).To(BeTrue())
			Expect(str.sendStream.finished()).To(BeFalse())
			Expect(str.finished()).To(BeFalse())
		})

		It("is not finished when the receive side is finished", func() {
			str.sendStream.closeForShutdown(errors.New("shutdown"))
			Expect(str.receiveStream.finished()).To(BeFalse())
			Expect(str.sendStream.finished()).To(BeTrue())
			Expect(str.finished()).To(BeFalse())
		})

		It("is not finished when the send side is finished", func() {
			str.closeForShutdown(errors.New("shutdown"))
			Expect(str.receiveStream.finished()).To(BeTrue())
			Expect(str.sendStream.finished()).To(BeTrue())
			Expect(str.finished()).To(BeTrue())
		})
	})
})
