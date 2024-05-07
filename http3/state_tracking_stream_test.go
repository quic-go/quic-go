package http3

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"

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
	It("recognizes when the receive side is closed", func() {
		qstr := mockquic.NewMockStream(mockCtrl)
		qstr.EXPECT().StreamID().AnyTimes()
		qstr.EXPECT().Context().Return(context.Background()).AnyTimes()
		var states []stateTransition
		str := newStateTrackingStream(qstr, func(state streamState, err error) {
			states = append(states, stateTransition{state, err})
		})

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

	It("recognizes local read cancellations", func() {
		qstr := mockquic.NewMockStream(mockCtrl)
		qstr.EXPECT().StreamID().AnyTimes()
		qstr.EXPECT().Context().Return(context.Background()).AnyTimes()
		var states []stateTransition
		str := newStateTrackingStream(qstr, func(state streamState, err error) {
			states = append(states, stateTransition{state, err})
		})

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

	It("recognizes remote cancellations", func() {
		qstr := mockquic.NewMockStream(mockCtrl)
		qstr.EXPECT().StreamID().AnyTimes()
		qstr.EXPECT().Context().Return(context.Background()).AnyTimes()
		var states []stateTransition
		str := newStateTrackingStream(qstr, func(state streamState, err error) {
			states = append(states, stateTransition{state, err})
		})

		testErr := errors.New("test error")
		qstr.EXPECT().Read(gomock.Any()).Return(0, testErr)
		_, err := str.Read(make([]byte, 3))
		Expect(err).To(MatchError(testErr))
		Expect(states).To(HaveLen(1))
		Expect(states[0].state).To(Equal(streamStateReceiveClosed))
		Expect(states[0].err).To(MatchError(testErr))
	})

	It("doesn't misinterpret read deadline errors", func() {
		qstr := mockquic.NewMockStream(mockCtrl)
		qstr.EXPECT().StreamID().AnyTimes()
		qstr.EXPECT().Context().Return(context.Background()).AnyTimes()
		var states []stateTransition
		str := newStateTrackingStream(qstr, func(state streamState, err error) {
			states = append(states, stateTransition{state, err})
		})

		qstr.EXPECT().Read(gomock.Any()).Return(0, os.ErrDeadlineExceeded)
		_, err := str.Read(make([]byte, 3))
		Expect(err).To(MatchError(os.ErrDeadlineExceeded))
		Expect(states).To(BeEmpty())
	})

	It("recognizes when the send side is closed, when write errors", func() {
		qstr := mockquic.NewMockStream(mockCtrl)
		qstr.EXPECT().StreamID().AnyTimes()
		qstr.EXPECT().Context().Return(context.Background()).AnyTimes()
		var states []stateTransition
		str := newStateTrackingStream(qstr, func(state streamState, err error) {
			states = append(states, stateTransition{state, err})
		})

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

	It("recognizes when the send side is closed, when write errors", func() {
		qstr := mockquic.NewMockStream(mockCtrl)
		qstr.EXPECT().StreamID().AnyTimes()
		qstr.EXPECT().Context().Return(context.Background()).AnyTimes()
		var states []stateTransition
		str := newStateTrackingStream(qstr, func(state streamState, err error) {
			states = append(states, stateTransition{state, err})
		})

		qstr.EXPECT().Write([]byte("foo")).Return(0, os.ErrDeadlineExceeded)
		Expect(states).To(BeEmpty())
		_, err := str.Write([]byte("foo"))
		Expect(err).To(MatchError(os.ErrDeadlineExceeded))
		Expect(states).To(BeEmpty())
	})

	It("recognizes when the send side is closed, when CancelWrite is called", func() {
		qstr := mockquic.NewMockStream(mockCtrl)
		qstr.EXPECT().StreamID().AnyTimes()
		qstr.EXPECT().Context().Return(context.Background()).AnyTimes()
		var states []stateTransition
		str := newStateTrackingStream(qstr, func(state streamState, err error) {
			states = append(states, stateTransition{state, err})
		})

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

	It("recognizes when the send side is closed, when the stream context is canceled", func() {
		qstr := mockquic.NewMockStream(mockCtrl)
		qstr.EXPECT().StreamID().AnyTimes()
		ctx, cancel := context.WithCancelCause(context.Background())
		qstr.EXPECT().Context().Return(ctx).AnyTimes()
		var states []stateTransition

		done := make(chan struct{})
		newStateTrackingStream(qstr, func(state streamState, err error) {
			states = append(states, stateTransition{state, err})
			close(done)
		})

		Expect(states).To(BeEmpty())
		testErr := errors.New("test error")
		cancel(testErr)
		Eventually(done).Should(BeClosed())
		Expect(states).To(HaveLen(1))
		Expect(states[0].state).To(Equal(streamStateSendClosed))
		Expect(states[0].err).To(Equal(testErr))
	})
})
