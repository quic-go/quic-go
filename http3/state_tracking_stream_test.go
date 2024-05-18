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

var someStreamID = quic.StreamID(12)

var _ = Describe("State Tracking Stream", func() {
	It("recognizes when the receive side is closed", func() {
		qstr := mockquic.NewMockStream(mockCtrl)
		qstr.EXPECT().StreamID().AnyTimes().Return(someStreamID)
		qstr.EXPECT().Context().Return(context.Background()).AnyTimes()

		var (
			clearer mockStreamClearer
			setter  mockErrorSetter
			str     = newStateTrackingStream(qstr, &clearer, &setter)
		)

		buf := bytes.NewBuffer([]byte("foobar"))
		qstr.EXPECT().Read(gomock.Any()).DoAndReturn(buf.Read).AnyTimes()
		for i := 0; i < 3; i++ {
			_, err := str.Read([]byte{0})
			Expect(err).ToNot(HaveOccurred())
			Expect(clearer.cleared).To(BeNil())
			Expect(setter.recvErrs).To(BeEmpty())
			Expect(setter.sendErrs).To(BeEmpty())
		}
		_, err := io.ReadAll(str)
		Expect(err).ToNot(HaveOccurred())
		Expect(clearer.cleared).To(BeNil())
		Expect(setter.recvErrs).To(HaveLen(1))
		Expect(setter.recvErrs[0]).To(Equal(io.EOF))
		Expect(setter.sendErrs).To(BeEmpty())
	})

	It("recognizes local read cancellations", func() {
		qstr := mockquic.NewMockStream(mockCtrl)
		qstr.EXPECT().StreamID().AnyTimes().Return(someStreamID)
		qstr.EXPECT().Context().Return(context.Background()).AnyTimes()

		var (
			clearer mockStreamClearer
			setter  mockErrorSetter
			str     = newStateTrackingStream(qstr, &clearer, &setter)
		)

		buf := bytes.NewBuffer([]byte("foobar"))
		qstr.EXPECT().Read(gomock.Any()).DoAndReturn(buf.Read).AnyTimes()
		qstr.EXPECT().CancelRead(quic.StreamErrorCode(1337))
		_, err := str.Read(make([]byte, 3))
		Expect(err).ToNot(HaveOccurred())
		Expect(clearer.cleared).To(BeNil())
		Expect(setter.recvErrs).To(BeEmpty())
		Expect(setter.sendErrs).To(BeEmpty())

		str.CancelRead(1337)
		Expect(clearer.cleared).To(BeNil())
		Expect(setter.recvErrs).To(HaveLen(1))
		Expect(setter.recvErrs[0]).To(Equal(&quic.StreamError{StreamID: someStreamID, ErrorCode: 1337}))
		Expect(setter.sendErrs).To(BeEmpty())
	})

	It("recognizes remote cancellations", func() {
		qstr := mockquic.NewMockStream(mockCtrl)
		qstr.EXPECT().StreamID().AnyTimes().Return(someStreamID)
		qstr.EXPECT().Context().Return(context.Background()).AnyTimes()

		var (
			clearer mockStreamClearer
			setter  mockErrorSetter
			str     = newStateTrackingStream(qstr, &clearer, &setter)
		)

		testErr := errors.New("test error")
		qstr.EXPECT().Read(gomock.Any()).Return(0, testErr)
		_, err := str.Read(make([]byte, 3))
		Expect(err).To(MatchError(testErr))
		Expect(clearer.cleared).To(BeNil())
		Expect(setter.recvErrs).To(HaveLen(1))
		Expect(setter.recvErrs[0]).To(Equal(testErr))
		Expect(setter.sendErrs).To(BeEmpty())
	})

	It("doesn't misinterpret read deadline errors", func() {
		qstr := mockquic.NewMockStream(mockCtrl)
		qstr.EXPECT().StreamID().AnyTimes().Return(someStreamID)
		qstr.EXPECT().Context().Return(context.Background()).AnyTimes()

		var (
			clearer mockStreamClearer
			setter  mockErrorSetter
			str     = newStateTrackingStream(qstr, &clearer, &setter)
		)

		qstr.EXPECT().Read(gomock.Any()).Return(0, os.ErrDeadlineExceeded)
		_, err := str.Read(make([]byte, 3))
		Expect(err).To(MatchError(os.ErrDeadlineExceeded))
		Expect(clearer.cleared).To(BeNil())
		Expect(setter.recvErrs).To(BeEmpty())
		Expect(setter.sendErrs).To(BeEmpty())
	})

	It("recognizes when the send side is closed, when write errors", func() {
		qstr := mockquic.NewMockStream(mockCtrl)
		qstr.EXPECT().StreamID().AnyTimes().Return(someStreamID)
		qstr.EXPECT().Context().Return(context.Background()).AnyTimes()

		var (
			clearer mockStreamClearer
			setter  mockErrorSetter
			str     = newStateTrackingStream(qstr, &clearer, &setter)
		)

		testErr := errors.New("test error")
		qstr.EXPECT().Write([]byte("foo")).Return(3, nil)
		qstr.EXPECT().Write([]byte("bar")).Return(0, testErr)

		_, err := str.Write([]byte("foo"))
		Expect(err).ToNot(HaveOccurred())
		Expect(clearer.cleared).To(BeNil())
		Expect(setter.recvErrs).To(BeEmpty())
		Expect(setter.sendErrs).To(BeEmpty())

		_, err = str.Write([]byte("bar"))
		Expect(err).To(MatchError(testErr))
		Expect(clearer.cleared).To(BeNil())
		Expect(setter.recvErrs).To(BeEmpty())
		Expect(setter.sendErrs).To(HaveLen(1))
		Expect(setter.sendErrs[0]).To(Equal(testErr))
	})

	It("recognizes when the send side is closed, when write errors", func() {
		qstr := mockquic.NewMockStream(mockCtrl)
		qstr.EXPECT().StreamID().AnyTimes().Return(someStreamID)
		qstr.EXPECT().Context().Return(context.Background()).AnyTimes()

		var (
			clearer mockStreamClearer
			setter  mockErrorSetter
			str     = newStateTrackingStream(qstr, &clearer, &setter)
		)

		qstr.EXPECT().Write([]byte("foo")).Return(0, os.ErrDeadlineExceeded)
		Expect(clearer.cleared).To(BeNil())
		Expect(setter.recvErrs).To(BeEmpty())
		Expect(setter.sendErrs).To(BeEmpty())

		_, err := str.Write([]byte("foo"))
		Expect(err).To(MatchError(os.ErrDeadlineExceeded))
		Expect(clearer.cleared).To(BeNil())
		Expect(setter.recvErrs).To(BeEmpty())
		Expect(setter.sendErrs).To(BeEmpty())
	})

	It("recognizes when the send side is closed, when CancelWrite is called", func() {
		qstr := mockquic.NewMockStream(mockCtrl)
		qstr.EXPECT().StreamID().AnyTimes().Return(someStreamID)
		qstr.EXPECT().Context().Return(context.Background()).AnyTimes()

		var (
			clearer mockStreamClearer
			setter  mockErrorSetter
			str     = newStateTrackingStream(qstr, &clearer, &setter)
		)

		qstr.EXPECT().Write(gomock.Any())
		qstr.EXPECT().CancelWrite(quic.StreamErrorCode(1337))
		_, err := str.Write([]byte("foobar"))
		Expect(err).ToNot(HaveOccurred())
		Expect(clearer.cleared).To(BeNil())
		Expect(setter.recvErrs).To(BeEmpty())
		Expect(setter.sendErrs).To(BeEmpty())

		str.CancelWrite(1337)
		Expect(clearer.cleared).To(BeNil())
		Expect(setter.recvErrs).To(BeEmpty())
		Expect(setter.sendErrs).To(HaveLen(1))
		Expect(setter.sendErrs[0]).To(Equal(&quic.StreamError{StreamID: someStreamID, ErrorCode: 1337}))
	})

	It("recognizes when the send side is closed, when the stream context is canceled", func() {
		qstr := mockquic.NewMockStream(mockCtrl)
		qstr.EXPECT().StreamID().AnyTimes()
		ctx, cancel := context.WithCancelCause(context.Background())
		qstr.EXPECT().Context().Return(ctx).AnyTimes()

		var (
			clearer mockStreamClearer
			setter  = mockErrorSetter{
				sendSent: make(chan struct{}),
			}
		)

		_ = newStateTrackingStream(qstr, &clearer, &setter)
		Expect(clearer.cleared).To(BeNil())
		Expect(setter.recvErrs).To(BeEmpty())
		Expect(setter.sendErrs).To(BeEmpty())

		testErr := errors.New("test error")
		cancel(testErr)
		Eventually(setter.sendSent).Should(BeClosed())
		Expect(clearer.cleared).To(BeNil())
		Expect(setter.recvErrs).To(BeEmpty())
		Expect(setter.sendErrs).To(HaveLen(1))
		Expect(setter.sendErrs[0]).To(Equal(testErr))
	})

	It("clears the stream when receive is closed followed by send is closed", func() {
		qstr := mockquic.NewMockStream(mockCtrl)
		qstr.EXPECT().StreamID().AnyTimes().Return(someStreamID)
		qstr.EXPECT().Context().Return(context.Background()).AnyTimes()

		var (
			clearer mockStreamClearer
			setter  mockErrorSetter
			str     = newStateTrackingStream(qstr, &clearer, &setter)
		)

		buf := bytes.NewBuffer([]byte("foobar"))
		qstr.EXPECT().Read(gomock.Any()).DoAndReturn(buf.Read).AnyTimes()
		_, err := io.ReadAll(str)
		Expect(err).ToNot(HaveOccurred())

		Expect(clearer.cleared).To(BeNil())
		Expect(setter.recvErrs).To(HaveLen(1))
		Expect(setter.recvErrs[0]).To(Equal(io.EOF))

		testErr := errors.New("test error")
		qstr.EXPECT().Write([]byte("bar")).Return(0, testErr)

		_, err = str.Write([]byte("bar"))
		Expect(err).To(MatchError(testErr))
		Expect(setter.sendErrs).To(HaveLen(1))
		Expect(setter.sendErrs[0]).To(Equal(testErr))

		Expect(clearer.cleared).To(Equal(&someStreamID))
	})

	It("clears the stream when send is closed followed by receive is closed", func() {
		qstr := mockquic.NewMockStream(mockCtrl)
		qstr.EXPECT().StreamID().AnyTimes().Return(someStreamID)
		qstr.EXPECT().Context().Return(context.Background()).AnyTimes()

		var (
			clearer mockStreamClearer
			setter  mockErrorSetter
			str     = newStateTrackingStream(qstr, &clearer, &setter)
		)

		testErr := errors.New("test error")
		qstr.EXPECT().Write([]byte("bar")).Return(0, testErr)

		_, err := str.Write([]byte("bar"))
		Expect(err).To(MatchError(testErr))
		Expect(clearer.cleared).To(BeNil())
		Expect(setter.sendErrs).To(HaveLen(1))
		Expect(setter.sendErrs[0]).To(Equal(testErr))

		buf := bytes.NewBuffer([]byte("foobar"))
		qstr.EXPECT().Read(gomock.Any()).DoAndReturn(buf.Read).AnyTimes()

		_, err = io.ReadAll(str)
		Expect(err).ToNot(HaveOccurred())
		Expect(setter.recvErrs).To(HaveLen(1))
		Expect(setter.recvErrs[0]).To(Equal(io.EOF))

		Expect(clearer.cleared).To(Equal(&someStreamID))
	})
})

type mockStreamClearer struct {
	cleared *quic.StreamID
}

func (s *mockStreamClearer) clearStream(id quic.StreamID) {
	s.cleared = &id
}

type mockErrorSetter struct {
	sendErrs []error
	recvErrs []error

	sendSent chan struct{}
}

func (e *mockErrorSetter) SetSendError(err error) {
	e.sendErrs = append(e.sendErrs, err)

	if e.sendSent != nil {
		close(e.sendSent)
	}
}

func (e *mockErrorSetter) SetReceiveError(err error) {
	e.recvErrs = append(e.recvErrs, err)
}
