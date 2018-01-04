package quic

import (
	"errors"

	"github.com/golang/mock/gomock"
	"github.com/lucas-clemente/quic-go/internal/handshake"
	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/wire"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Streams Map (for IETF QUIC)", func() {
	var m *streamsMap

	newStream := func(id protocol.StreamID) streamI {
		str := NewMockStreamI(mockCtrl)
		str.EXPECT().StreamID().Return(id).AnyTimes()
		return str
	}

	setNewStreamsMap := func(p protocol.Perspective) {
		m = newStreamsMap(newStream, p).(*streamsMap)
	}

	deleteStream := func(id protocol.StreamID) {
		ExpectWithOffset(1, m.DeleteStream(id)).To(Succeed())
	}

	Context("getting and creating streams", func() {
		Context("as a server", func() {
			BeforeEach(func() {
				setNewStreamsMap(protocol.PerspectiveServer)
			})

			Context("client-side streams", func() {
				It("gets new streams", func() {
					s, err := m.GetOrOpenStream(1)
					Expect(err).NotTo(HaveOccurred())
					Expect(s).ToNot(BeNil())
					Expect(s.StreamID()).To(Equal(protocol.StreamID(1)))
					Expect(m.streams).To(HaveLen(1))
				})

				It("rejects streams with even IDs", func() {
					_, err := m.GetOrOpenStream(6)
					Expect(err).To(MatchError("InvalidStreamID: peer attempted to open stream 6"))
				})

				It("rejects streams with even IDs, which are lower thatn the highest client-side stream", func() {
					_, err := m.GetOrOpenStream(5)
					Expect(err).NotTo(HaveOccurred())
					_, err = m.GetOrOpenStream(4)
					Expect(err).To(MatchError("InvalidStreamID: peer attempted to open stream 4"))
				})

				It("gets existing streams", func() {
					s, err := m.GetOrOpenStream(5)
					Expect(err).NotTo(HaveOccurred())
					numStreams := len(m.streams)
					s, err = m.GetOrOpenStream(5)
					Expect(err).NotTo(HaveOccurred())
					Expect(s.StreamID()).To(Equal(protocol.StreamID(5)))
					Expect(m.streams).To(HaveLen(numStreams))
				})

				It("returns nil for closed streams", func() {
					_, err := m.GetOrOpenStream(5)
					Expect(err).NotTo(HaveOccurred())
					deleteStream(5)
					s, err := m.GetOrOpenStream(5)
					Expect(err).NotTo(HaveOccurred())
					Expect(s).To(BeNil())
				})

				It("opens skipped streams", func() {
					_, err := m.GetOrOpenStream(7)
					Expect(err).NotTo(HaveOccurred())
					Expect(m.streams).To(HaveKey(protocol.StreamID(3)))
					Expect(m.streams).To(HaveKey(protocol.StreamID(5)))
					Expect(m.streams).To(HaveKey(protocol.StreamID(7)))
				})

				It("doesn't reopen an already closed stream", func() {
					_, err := m.GetOrOpenStream(5)
					Expect(err).ToNot(HaveOccurred())
					deleteStream(5)
					Expect(err).ToNot(HaveOccurred())
					str, err := m.GetOrOpenStream(5)
					Expect(err).ToNot(HaveOccurred())
					Expect(str).To(BeNil())
				})
			})

			Context("server-side streams", func() {
				It("opens a stream 2 first", func() {
					s, err := m.OpenStream()
					Expect(err).ToNot(HaveOccurred())
					Expect(s).ToNot(BeNil())
					Expect(s.StreamID()).To(Equal(protocol.StreamID(2)))
				})

				It("returns the error when the streamsMap was closed", func() {
					testErr := errors.New("test error")
					m.CloseWithError(testErr)
					_, err := m.OpenStream()
					Expect(err).To(MatchError(testErr))
				})

				It("doesn't reopen an already closed stream", func() {
					str, err := m.OpenStream()
					Expect(err).ToNot(HaveOccurred())
					Expect(str.StreamID()).To(Equal(protocol.StreamID(2)))
					deleteStream(2)
					Expect(err).ToNot(HaveOccurred())
					str, err = m.GetOrOpenStream(2)
					Expect(err).ToNot(HaveOccurred())
					Expect(str).To(BeNil())
				})

				Context("opening streams synchronously", func() {
					It("immediately returns when OpenStreamSync is called after an error was registered", func() {
						testErr := errors.New("test error")
						m.CloseWithError(testErr)
						_, err := m.OpenStreamSync()
						Expect(err).To(MatchError(testErr))
					})
				})
			})

			Context("accepting streams", func() {
				It("does nothing if no stream is opened", func() {
					var accepted bool
					go func() {
						_, _ = m.AcceptStream()
						accepted = true
					}()
					Consistently(func() bool { return accepted }).Should(BeFalse())
				})

				It("starts with stream 1", func() {
					var str Stream
					done := make(chan struct{})
					go func() {
						defer GinkgoRecover()
						var err error
						str, err = m.AcceptStream()
						Expect(err).ToNot(HaveOccurred())
						close(done)
					}()
					_, err := m.GetOrOpenStream(1)
					Expect(err).ToNot(HaveOccurred())
					Eventually(done).Should(BeClosed())
					Expect(str.StreamID()).To(Equal(protocol.StreamID(1)))
				})

				It("returns an implicitly opened stream, if a stream number is skipped", func() {
					var str Stream
					done := make(chan struct{})
					go func() {
						defer GinkgoRecover()
						var err error
						str, err = m.AcceptStream()
						Expect(err).ToNot(HaveOccurred())
						close(done)
					}()
					_, err := m.GetOrOpenStream(3)
					Expect(err).ToNot(HaveOccurred())
					Eventually(done).Should(BeClosed())
					Expect(str.StreamID()).To(Equal(protocol.StreamID(1)))
				})

				It("returns to multiple accepts", func() {
					var str1, str2 Stream
					done1 := make(chan struct{})
					done2 := make(chan struct{})
					go func() {
						defer GinkgoRecover()
						var err error
						str1, err = m.AcceptStream()
						Expect(err).ToNot(HaveOccurred())
						close(done1)
					}()
					go func() {
						defer GinkgoRecover()
						var err error
						str2, err = m.AcceptStream()
						Expect(err).ToNot(HaveOccurred())
						close(done2)
					}()
					_, err := m.GetOrOpenStream(3) // opens stream 1 and 3
					Expect(err).ToNot(HaveOccurred())
					Eventually(done1).Should(BeClosed())
					Eventually(done2).Should(BeClosed())
					Expect(str1.StreamID()).ToNot(Equal(str2.StreamID()))
					Expect(str1.StreamID() + str2.StreamID()).To(BeEquivalentTo(1 + 3))
				})

				It("waits until a new stream is available", func() {
					var str Stream
					done := make(chan struct{})
					go func() {
						defer GinkgoRecover()
						var err error
						str, err = m.AcceptStream()
						Expect(err).ToNot(HaveOccurred())
						close(done)
					}()
					Consistently(done).ShouldNot(BeClosed())
					_, err := m.GetOrOpenStream(1)
					Expect(err).ToNot(HaveOccurred())
					Eventually(done).Should(BeClosed())
					Expect(str.StreamID()).To(Equal(protocol.StreamID(1)))
				})

				It("returns multiple streams on subsequent Accept calls, if available", func() {
					var str Stream
					done := make(chan struct{})
					go func() {
						defer GinkgoRecover()
						var err error
						str, err = m.AcceptStream()
						Expect(err).ToNot(HaveOccurred())
						close(done)
					}()
					_, err := m.GetOrOpenStream(3)
					Expect(err).ToNot(HaveOccurred())
					Eventually(done).Should(BeClosed())
					Expect(str.StreamID()).To(Equal(protocol.StreamID(1)))
					str, err = m.AcceptStream()
					Expect(err).ToNot(HaveOccurred())
					Expect(str.StreamID()).To(Equal(protocol.StreamID(3)))
				})

				It("blocks after accepting a stream", func() {
					_, err := m.GetOrOpenStream(1)
					Expect(err).ToNot(HaveOccurred())
					str, err := m.AcceptStream()
					Expect(err).ToNot(HaveOccurred())
					Expect(str.StreamID()).To(Equal(protocol.StreamID(1)))
					done := make(chan struct{})
					go func() {
						defer GinkgoRecover()
						_, _ = m.AcceptStream()
						close(done)
					}()
					Consistently(done).ShouldNot(BeClosed())
					// make the go routine return
					str.(*MockStreamI).EXPECT().closeForShutdown(gomock.Any())
					m.CloseWithError(errors.New("shut down"))
					Eventually(done).Should(BeClosed())
				})

				It("stops waiting when an error is registered", func() {
					testErr := errors.New("testErr")
					done := make(chan struct{})
					go func() {
						defer GinkgoRecover()
						_, err := m.AcceptStream()
						Expect(err).To(MatchError(testErr))
						close(done)
					}()
					Consistently(done).ShouldNot(BeClosed())
					m.CloseWithError(testErr)
					Eventually(done).Should(BeClosed())
				})

				It("immediately returns when Accept is called after an error was registered", func() {
					testErr := errors.New("testErr")
					m.CloseWithError(testErr)
					_, err := m.AcceptStream()
					Expect(err).To(MatchError(testErr))
				})
			})
		})

		Context("as a client", func() {
			BeforeEach(func() {
				setNewStreamsMap(protocol.PerspectiveClient)
			})

			Context("server-side streams", func() {
				It("rejects streams with odd IDs", func() {
					_, err := m.GetOrOpenStream(5)
					Expect(err).To(MatchError("InvalidStreamID: peer attempted to open stream 5"))
				})

				It("rejects streams with odds IDs, which are lower than the highest server-side stream", func() {
					_, err := m.GetOrOpenStream(6)
					Expect(err).NotTo(HaveOccurred())
					_, err = m.GetOrOpenStream(5)
					Expect(err).To(MatchError("InvalidStreamID: peer attempted to open stream 5"))
				})

				It("gets new streams", func() {
					s, err := m.GetOrOpenStream(2)
					Expect(err).NotTo(HaveOccurred())
					Expect(s.StreamID()).To(Equal(protocol.StreamID(2)))
					Expect(m.streams).To(HaveLen(1))
				})

				It("opens skipped streams", func() {
					_, err := m.GetOrOpenStream(6)
					Expect(err).NotTo(HaveOccurred())
					Expect(m.streams).To(HaveKey(protocol.StreamID(2)))
					Expect(m.streams).To(HaveKey(protocol.StreamID(4)))
					Expect(m.streams).To(HaveKey(protocol.StreamID(6)))
				})

				It("doesn't reopen an already closed stream", func() {
					str, err := m.OpenStream()
					Expect(err).ToNot(HaveOccurred())
					Expect(str.StreamID()).To(Equal(protocol.StreamID(1)))
					deleteStream(1)
					Expect(err).ToNot(HaveOccurred())
					str, err = m.GetOrOpenStream(1)
					Expect(err).ToNot(HaveOccurred())
					Expect(str).To(BeNil())
				})
			})

			Context("client-side streams", func() {
				It("starts with stream 1", func() {
					setNewStreamsMap(protocol.PerspectiveClient)
					s, err := m.OpenStream()
					Expect(err).ToNot(HaveOccurred())
					Expect(s).ToNot(BeNil())
					Expect(s.StreamID()).To(BeEquivalentTo(1))
				})

				It("opens multiple streams", func() {
					s1, err := m.OpenStream()
					Expect(err).ToNot(HaveOccurred())
					s2, err := m.OpenStream()
					Expect(err).ToNot(HaveOccurred())
					Expect(s2.StreamID()).To(Equal(s1.StreamID() + 2))
				})

				It("doesn't reopen an already closed stream", func() {
					_, err := m.GetOrOpenStream(4)
					Expect(err).ToNot(HaveOccurred())
					deleteStream(4)
					Expect(err).ToNot(HaveOccurred())
					str, err := m.GetOrOpenStream(4)
					Expect(err).ToNot(HaveOccurred())
					Expect(str).To(BeNil())
				})
			})

			Context("accepting streams", func() {
				It("accepts stream 2 first", func() {
					var str Stream
					done := make(chan struct{})
					go func() {
						defer GinkgoRecover()
						var err error
						str, err = m.AcceptStream()
						Expect(err).ToNot(HaveOccurred())
						close(done)
					}()
					_, err := m.GetOrOpenStream(2)
					Expect(err).ToNot(HaveOccurred())
					Eventually(done).Should(BeClosed())
					Expect(str.StreamID()).To(Equal(protocol.StreamID(2)))
				})
			})
		})
	})

	Context("deleting streams", func() {
		BeforeEach(func() {
			setNewStreamsMap(protocol.PerspectiveServer)
		})

		It("deletes an incoming stream", func() {
			_, err := m.GetOrOpenStream(3) // open stream 1 and 3
			Expect(err).ToNot(HaveOccurred())
			err = m.DeleteStream(1)
			Expect(err).ToNot(HaveOccurred())
			Expect(m.streams).To(HaveLen(1))
			Expect(m.streams).To(HaveKey(protocol.StreamID(3)))
		})

		It("deletes an outgoing stream", func() {
			_, err := m.OpenStream() // open stream 2
			Expect(err).ToNot(HaveOccurred())
			_, err = m.OpenStream()
			Expect(err).ToNot(HaveOccurred())
			err = m.DeleteStream(2)
			Expect(err).ToNot(HaveOccurred())
		})

		It("errors when the stream doesn't exist", func() {
			err := m.DeleteStream(1337)
			Expect(err).To(MatchError(errMapAccess))
		})
	})

	It("sets the flow control limit", func() {
		setNewStreamsMap(protocol.PerspectiveServer)
		_, err := m.GetOrOpenStream(3)
		Expect(err).ToNot(HaveOccurred())
		m.streams[1].(*MockStreamI).EXPECT().handleMaxStreamDataFrame(&wire.MaxStreamDataFrame{
			StreamID:   1,
			ByteOffset: 321,
		})
		m.streams[3].(*MockStreamI).EXPECT().handleMaxStreamDataFrame(&wire.MaxStreamDataFrame{
			StreamID:   3,
			ByteOffset: 321,
		})
		m.UpdateLimits(&handshake.TransportParameters{StreamFlowControlWindow: 321})
	})
})
