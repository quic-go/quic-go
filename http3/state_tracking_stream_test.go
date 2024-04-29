package http3

import (
	"bytes"
	"errors"
	"io"

	"github.com/quic-go/quic-go"
	mockquic "github.com/quic-go/quic-go/internal/mocks/quic"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"go.uber.org/mock/gomock"
)

type stateTransition struct {
	state streamState
	err   error
}

var _ = Describe("State Tracking Stream", func() {
	var (
		qstr   *mockquic.MockStream
		str    *stateTrackingStream
		states []stateTransition
	)

	BeforeEach(func() {
		states = nil
		qstr = mockquic.NewMockStream(mockCtrl)
		qstr.EXPECT().StreamID().AnyTimes()
		str = newStateTrackingStream(qstr, func(state streamState, err error) {
			states = append(states, stateTransition{state, err})
		})
	})

	It("recognizes when the receive side is closed", func() {
		buf := bytes.NewBuffer([]byte("foobar"))
		qstr.EXPECT().Read(gomock.Any()).DoAndReturn(buf.Read).AnyTimes()
		for i := 0; i < 3; i++ {
			_, err := str.Read([]byte{0})
			Expect(err).ToNot(HaveOccurred())
			Expect(states).To(BeEmpty())
		}
		_, err := io.ReadAll(str)
		Expect(err).ToNot(HaveOccurred())
		Expect(states).To(HaveLen(1))
		Expect(states[0].state).To(Equal(streamStateReceiveClosed))
		Expect(states[0].err).To(Equal(io.EOF))
	})

	It("recognizes read cancellations", func() {
		buf := bytes.NewBuffer([]byte("foobar"))
		qstr.EXPECT().Read(gomock.Any()).DoAndReturn(buf.Read).AnyTimes()
		qstr.EXPECT().CancelRead(quic.StreamErrorCode(1337))
		_, err := str.Read(make([]byte, 3))
		Expect(err).ToNot(HaveOccurred())
		Expect(states).To(BeEmpty())
		str.CancelRead(1337)
		Expect(states).To(HaveLen(1))
		Expect(states[0].state).To(Equal(streamStateReceiveClosed))
		Expect(states[0].err).To(Equal(&quic.StreamError{ErrorCode: 1337}))
	})

	It("recognizes when the send side is closed", func() {
		testErr := errors.New("test error")
		qstr.EXPECT().Write([]byte("foo")).Return(3, nil)
		qstr.EXPECT().Write([]byte("bar")).Return(0, testErr)
		_, err := str.Write([]byte("foo"))
		Expect(err).ToNot(HaveOccurred())
		Expect(states).To(BeEmpty())
		_, err = str.Write([]byte("bar"))
		Expect(err).To(MatchError(testErr))
		Expect(states).To(HaveLen(1))
		Expect(states[0].state).To(Equal(streamStateSendClosed))
		Expect(states[0].err).To(Equal(testErr))
	})

	It("recognizes write cancellations", func() {
		qstr.EXPECT().Write(gomock.Any())
		qstr.EXPECT().CancelWrite(quic.StreamErrorCode(1337))
		_, err := str.Write([]byte("foobar"))
		Expect(err).ToNot(HaveOccurred())
		Expect(states).To(BeEmpty())
		str.CancelWrite(1337)
		Expect(states).To(HaveLen(1))
		Expect(states[0].state).To(Equal(streamStateSendClosed))
		Expect(states[0].err).To(Equal(&quic.StreamError{ErrorCode: 1337}))
	})
})
