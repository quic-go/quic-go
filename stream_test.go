package quic

import (
	"io"
	"os"
	"strconv"
	"time"

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
		str            *stream
		strWithTimeout io.ReadWriter // str wrapped with gbytes.Timeout{Reader,Writer}
		mockFC         *mocks.MockStreamFlowController
		mockSender     *MockStreamSender
	)

	BeforeEach(func() {
		mockSender = NewMockStreamSender(mockCtrl)
		mockFC = mocks.NewMockStreamFlowController(mockCtrl)
		str = newStream(streamID, mockSender, mockFC, protocol.VersionWhatever)

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

	Context("completing", func() {
		It("is not completed when only the receive side is completed", func() {
			// don't EXPECT a call to mockSender.onStreamCompleted()
			str.receiveStream.sender.onStreamCompleted(streamID)
		})

		It("is not completed when only the send side is completed", func() {
			// don't EXPECT a call to mockSender.onStreamCompleted()
			str.sendStream.sender.onStreamCompleted(streamID)
		})

		It("is completed when both sides are completed", func() {
			mockSender.EXPECT().onStreamCompleted(streamID)
			str.sendStream.sender.onStreamCompleted(streamID)
			str.receiveStream.sender.onStreamCompleted(streamID)
		})
	})
})
