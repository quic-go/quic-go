package quic

import (
	"errors"
	"sort"

	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/qerr"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Streams Map", func() {
	var m *streamsMap

	newStream := func(id protocol.StreamID) streamI {
		str := NewMockStreamI(mockCtrl)
		str.EXPECT().StreamID().Return(id).AnyTimes()
		return str
	}

	setNewStreamsMap := func(p protocol.Perspective, v protocol.VersionNumber) {
		m = newStreamsMap(newStream, p, v)
	}

	deleteStream := func(id protocol.StreamID) {
		ExpectWithOffset(1, m.DeleteStream(id)).To(Succeed())
	}

	Context("getting and creating streams", func() {
		Context("as a server", func() {
			BeforeEach(func() {
				setNewStreamsMap(protocol.PerspectiveServer, versionGQUICFrames)
			})

			Context("client-side streams", func() {
				It("gets new streams", func() {
					s, err := m.GetOrOpenStream(3)
					Expect(err).NotTo(HaveOccurred())
					Expect(s).ToNot(BeNil())
					Expect(s.StreamID()).To(Equal(protocol.StreamID(3)))
					Expect(m.streams).To(HaveLen(1))
					Expect(m.numIncomingStreams).To(BeEquivalentTo(1))
					Expect(m.numOutgoingStreams).To(BeZero())
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
					numStreams := m.numIncomingStreams
					s, err = m.GetOrOpenStream(5)
					Expect(err).NotTo(HaveOccurred())
					Expect(s.StreamID()).To(Equal(protocol.StreamID(5)))
					Expect(m.numIncomingStreams).To(Equal(numStreams))
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

				Context("counting streams", func() {
					It("errors when too many streams are opened", func() {
						for i := uint32(0); i < m.maxIncomingStreams; i++ {
							_, err := m.GetOrOpenStream(protocol.StreamID(i*2 + 1))
							Expect(err).NotTo(HaveOccurred())
						}
						_, err := m.GetOrOpenStream(protocol.StreamID(2*m.maxIncomingStreams + 3))
						Expect(err).To(MatchError(qerr.TooManyOpenStreams))
					})

					It("errors when too many streams are opened implicitely", func() {
						_, err := m.GetOrOpenStream(protocol.StreamID(m.maxIncomingStreams*2 + 3))
						Expect(err).To(MatchError(qerr.TooManyOpenStreams))
					})

					It("does not error when many streams are opened and closed", func() {
						for i := uint32(2); i < 10*m.maxIncomingStreams; i++ {
							str, err := m.GetOrOpenStream(protocol.StreamID(i*2 + 1))
							Expect(err).NotTo(HaveOccurred())
							deleteStream(str.StreamID())
						}
					})
				})
			})

			Context("server-side streams", func() {
				It("doesn't allow opening streams before receiving the transport parameters", func() {
					_, err := m.OpenStream()
					Expect(err).To(MatchError(qerr.TooManyOpenStreams))
				})

				It("opens a stream 2 first", func() {
					m.UpdateMaxStreamLimit(100)
					s, err := m.OpenStream()
					Expect(err).ToNot(HaveOccurred())
					Expect(s).ToNot(BeNil())
					Expect(s.StreamID()).To(Equal(protocol.StreamID(2)))
					Expect(m.numIncomingStreams).To(BeZero())
					Expect(m.numOutgoingStreams).To(BeEquivalentTo(1))
				})

				It("returns the error when the streamsMap was closed", func() {
					testErr := errors.New("test error")
					m.CloseWithError(testErr)
					_, err := m.OpenStream()
					Expect(err).To(MatchError(testErr))
				})

				It("doesn't reopen an already closed stream", func() {
					m.UpdateMaxStreamLimit(100)
					str, err := m.OpenStream()
					Expect(err).ToNot(HaveOccurred())
					Expect(str.StreamID()).To(Equal(protocol.StreamID(2)))
					deleteStream(2)
					Expect(err).ToNot(HaveOccurred())
					str, err = m.GetOrOpenStream(2)
					Expect(err).ToNot(HaveOccurred())
					Expect(str).To(BeNil())
				})

				Context("counting streams", func() {
					const maxOutgoingStreams = 50

					BeforeEach(func() {
						m.UpdateMaxStreamLimit(maxOutgoingStreams)
					})

					It("errors when too many streams are opened", func() {
						for i := 1; i <= maxOutgoingStreams; i++ {
							_, err := m.OpenStream()
							Expect(err).NotTo(HaveOccurred())
						}
						_, err := m.OpenStream()
						Expect(err).To(MatchError(qerr.TooManyOpenStreams))
					})

					It("does not error when many streams are opened and closed", func() {
						for i := 2; i < 10*maxOutgoingStreams; i++ {
							str, err := m.OpenStream()
							Expect(err).NotTo(HaveOccurred())
							deleteStream(str.StreamID())
						}
					})

					It("allows many server- and client-side streams at the same time", func() {
						for i := 1; i < maxOutgoingStreams; i++ {
							_, err := m.OpenStream()
							Expect(err).ToNot(HaveOccurred())
						}
						for i := 0; i < maxOutgoingStreams; i++ {
							_, err := m.GetOrOpenStream(protocol.StreamID(2*i + 1))
							Expect(err).ToNot(HaveOccurred())
						}
					})
				})

				Context("opening streams synchronously", func() {
					const maxOutgoingStreams = 10

					BeforeEach(func() {
						m.UpdateMaxStreamLimit(maxOutgoingStreams)
					})

					openMaxNumStreams := func() {
						for i := 1; i <= maxOutgoingStreams; i++ {
							_, err := m.OpenStream()
							Expect(err).NotTo(HaveOccurred())
						}
						_, err := m.OpenStream()
						Expect(err).To(MatchError(qerr.TooManyOpenStreams))
					}

					It("waits until another stream is closed", func() {
						openMaxNumStreams()
						var returned bool
						var str streamI
						go func() {
							defer GinkgoRecover()
							var err error
							str, err = m.OpenStreamSync()
							Expect(err).ToNot(HaveOccurred())
							returned = true
						}()

						Consistently(func() bool { return returned }).Should(BeFalse())
						deleteStream(6)
						Eventually(func() bool { return returned }).Should(BeTrue())
						Expect(str.StreamID()).To(Equal(protocol.StreamID(2*maxOutgoingStreams + 2)))
					})

					It("stops waiting when an error is registered", func() {
						testErr := errors.New("test error")
						openMaxNumStreams()
						for _, str := range m.streams {
							str.(*MockStreamI).EXPECT().closeForShutdown(testErr)
						}

						done := make(chan struct{})
						go func() {
							defer GinkgoRecover()
							_, err := m.OpenStreamSync()
							Expect(err).To(MatchError(testErr))
							close(done)
						}()

						Consistently(done).ShouldNot(BeClosed())
						m.CloseWithError(testErr)
						Eventually(done).Should(BeClosed())
					})

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

				It("starts with stream 1, if the crypto stream is stream 0", func() {
					setNewStreamsMap(protocol.PerspectiveServer, versionIETFFrames)
					var str streamI
					go func() {
						defer GinkgoRecover()
						var err error
						str, err = m.AcceptStream()
						Expect(err).ToNot(HaveOccurred())
					}()
					_, err := m.GetOrOpenStream(1)
					Expect(err).ToNot(HaveOccurred())
					Eventually(func() Stream { return str }).ShouldNot(BeNil())
					Expect(str.StreamID()).To(Equal(protocol.StreamID(1)))
				})

				It("starts with stream 3, if the crypto stream is stream 1", func() {
					var str streamI
					go func() {
						defer GinkgoRecover()
						var err error
						str, err = m.AcceptStream()
						Expect(err).ToNot(HaveOccurred())
					}()
					_, err := m.GetOrOpenStream(3)
					Expect(err).ToNot(HaveOccurred())
					Eventually(func() Stream { return str }).ShouldNot(BeNil())
					Expect(str.StreamID()).To(Equal(protocol.StreamID(3)))
				})

				It("returns an implicitly opened stream, if a stream number is skipped", func() {
					var str streamI
					go func() {
						defer GinkgoRecover()
						var err error
						str, err = m.AcceptStream()
						Expect(err).ToNot(HaveOccurred())
					}()
					_, err := m.GetOrOpenStream(5)
					Expect(err).ToNot(HaveOccurred())
					Eventually(func() Stream { return str }).ShouldNot(BeNil())
					Expect(str.StreamID()).To(Equal(protocol.StreamID(3)))
				})

				It("returns to multiple accepts", func() {
					var str1, str2 streamI
					go func() {
						defer GinkgoRecover()
						var err error
						str1, err = m.AcceptStream()
						Expect(err).ToNot(HaveOccurred())
					}()
					go func() {
						defer GinkgoRecover()
						var err error
						str2, err = m.AcceptStream()
						Expect(err).ToNot(HaveOccurred())
					}()
					_, err := m.GetOrOpenStream(5) // opens stream 3 and 5
					Expect(err).ToNot(HaveOccurred())
					Eventually(func() streamI { return str1 }).ShouldNot(BeNil())
					Eventually(func() streamI { return str2 }).ShouldNot(BeNil())
					Expect(str1.StreamID()).ToNot(Equal(str2.StreamID()))
					Expect(str1.StreamID() + str2.StreamID()).To(BeEquivalentTo(3 + 5))
				})

				It("waits a new stream is available", func() {
					var str streamI
					go func() {
						defer GinkgoRecover()
						var err error
						str, err = m.AcceptStream()
						Expect(err).ToNot(HaveOccurred())
					}()
					Consistently(func() streamI { return str }).Should(BeNil())
					_, err := m.GetOrOpenStream(3)
					Expect(err).ToNot(HaveOccurred())
					Eventually(func() streamI { return str }).ShouldNot(BeNil())
					Expect(str.StreamID()).To(Equal(protocol.StreamID(3)))
				})

				It("returns multiple streams on subsequent Accept calls, if available", func() {
					var str streamI
					go func() {
						defer GinkgoRecover()
						var err error
						str, err = m.AcceptStream()
						Expect(err).ToNot(HaveOccurred())
					}()
					_, err := m.GetOrOpenStream(5)
					Expect(err).ToNot(HaveOccurred())
					Eventually(func() streamI { return str }).ShouldNot(BeNil())
					Expect(str.StreamID()).To(Equal(protocol.StreamID(3)))
					str, err = m.AcceptStream()
					Expect(err).ToNot(HaveOccurred())
					Expect(str.StreamID()).To(Equal(protocol.StreamID(5)))
				})

				It("blocks after accepting a stream", func() {
					var accepted bool
					_, err := m.GetOrOpenStream(3)
					Expect(err).ToNot(HaveOccurred())
					str, err := m.AcceptStream()
					Expect(err).ToNot(HaveOccurred())
					Expect(str.StreamID()).To(Equal(protocol.StreamID(3)))
					go func() {
						defer GinkgoRecover()
						_, _ = m.AcceptStream()
						accepted = true
					}()
					Consistently(func() bool { return accepted }).Should(BeFalse())
				})

				It("stops waiting when an error is registered", func() {
					testErr := errors.New("testErr")
					var acceptErr error
					go func() {
						_, acceptErr = m.AcceptStream()
					}()
					Consistently(func() error { return acceptErr }).ShouldNot(HaveOccurred())
					m.CloseWithError(testErr)
					Eventually(func() error { return acceptErr }).Should(MatchError(testErr))
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
				setNewStreamsMap(protocol.PerspectiveClient, versionGQUICFrames)
				m.UpdateMaxStreamLimit(100)
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
					Expect(m.numOutgoingStreams).To(BeZero())
					Expect(m.numIncomingStreams).To(BeEquivalentTo(1))
				})

				It("opens skipped streams", func() {
					_, err := m.GetOrOpenStream(6)
					Expect(err).NotTo(HaveOccurred())
					Expect(m.streams).To(HaveKey(protocol.StreamID(2)))
					Expect(m.streams).To(HaveKey(protocol.StreamID(4)))
					Expect(m.streams).To(HaveKey(protocol.StreamID(6)))
					Expect(m.numOutgoingStreams).To(BeZero())
					Expect(m.numIncomingStreams).To(BeEquivalentTo(3))
				})

				It("doesn't reopen an already closed stream", func() {
					str, err := m.OpenStream()
					Expect(err).ToNot(HaveOccurred())
					Expect(str.StreamID()).To(Equal(protocol.StreamID(3)))
					deleteStream(3)
					Expect(err).ToNot(HaveOccurred())
					str, err = m.GetOrOpenStream(3)
					Expect(err).ToNot(HaveOccurred())
					Expect(str).To(BeNil())
				})
			})

			Context("client-side streams", func() {
				It("starts with stream 1, if the crypto stream is stream 0", func() {
					setNewStreamsMap(protocol.PerspectiveClient, versionIETFFrames)
					m.UpdateMaxStreamLimit(100)
					s, err := m.OpenStream()
					Expect(err).ToNot(HaveOccurred())
					Expect(s).ToNot(BeNil())
					Expect(s.StreamID()).To(BeEquivalentTo(1))
					Expect(m.numOutgoingStreams).To(BeEquivalentTo(1))
					Expect(m.numIncomingStreams).To(BeZero())
				})

				It("starts with stream 3, if the crypto stream is stream 1", func() {
					s, err := m.OpenStream()
					Expect(err).ToNot(HaveOccurred())
					Expect(s).ToNot(BeNil())
					Expect(s.StreamID()).To(BeEquivalentTo(3))
					Expect(m.numOutgoingStreams).To(BeEquivalentTo(1))
					Expect(m.numIncomingStreams).To(BeZero())
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
					var str streamI
					go func() {
						defer GinkgoRecover()
						var err error
						str, err = m.AcceptStream()
						Expect(err).ToNot(HaveOccurred())
					}()
					_, err := m.GetOrOpenStream(2)
					Expect(err).ToNot(HaveOccurred())
					Eventually(func() streamI { return str }).ShouldNot(BeNil())
					Expect(str.StreamID()).To(Equal(protocol.StreamID(2)))
				})
			})
		})
	})

	Context("Ranging", func() {
		It("ranges over all open streams", func() {
			setNewStreamsMap(protocol.PerspectiveServer, protocol.VersionWhatever)
			var callbackCalledForStream []protocol.StreamID
			callback := func(str streamI) {
				callbackCalledForStream = append(callbackCalledForStream, str.StreamID())
				sort.Slice(callbackCalledForStream, func(i, j int) bool {
					return callbackCalledForStream[i] < callbackCalledForStream[j]
				})
			}

			Expect(m.streams).To(BeEmpty())
			// create 5 streams, ids 4 to 8
			callbackCalledForStream = callbackCalledForStream[:0]
			for i := 4; i <= 8; i++ {
				str := NewMockStreamI(mockCtrl)
				str.EXPECT().StreamID().Return(protocol.StreamID(i)).AnyTimes()
				err := m.putStream(str)
				Expect(err).NotTo(HaveOccurred())
			}
			// execute the callback for all streams
			m.Range(callback)
			Expect(callbackCalledForStream).To(Equal([]protocol.StreamID{4, 5, 6, 7, 8}))
		})
	})

	Context("deleting streams", func() {
		BeforeEach(func() {
			setNewStreamsMap(protocol.PerspectiveServer, versionGQUICFrames)
		})

		It("deletes an incoming stream", func() {
			_, err := m.GetOrOpenStream(5) // open stream 3 and 5
			Expect(err).ToNot(HaveOccurred())
			Expect(m.numIncomingStreams).To(BeEquivalentTo(2))
			err = m.DeleteStream(3)
			Expect(err).ToNot(HaveOccurred())
			Expect(m.streams).To(HaveLen(1))
			Expect(m.streams).To(HaveKey(protocol.StreamID(5)))
			Expect(m.numIncomingStreams).To(BeEquivalentTo(1))
		})

		It("deletes an outgoing stream", func() {
			m.UpdateMaxStreamLimit(10000)
			_, err := m.OpenStream() // open stream 2
			Expect(err).ToNot(HaveOccurred())
			_, err = m.OpenStream()
			Expect(err).ToNot(HaveOccurred())
			Expect(m.numOutgoingStreams).To(BeEquivalentTo(2))
			err = m.DeleteStream(2)
			Expect(err).ToNot(HaveOccurred())
			Expect(m.numOutgoingStreams).To(BeEquivalentTo(1))
		})

		It("errors when the stream doesn't exist", func() {
			err := m.DeleteStream(1337)
			Expect(err).To(MatchError(errMapAccess))
		})
	})
})
