package quic

import (
	"errors"
	"math"
	"time"

	"github.com/lucas-clemente/quic-go/handshake"
	"github.com/lucas-clemente/quic-go/protocol"
	"github.com/lucas-clemente/quic-go/qerr"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

type mockConnectionParametersManager struct {
	maxIncomingStreams uint32
	maxOutgoingStreams uint32
	idleTime           time.Duration
}

func (m *mockConnectionParametersManager) SetFromMap(map[handshake.Tag][]byte) error {
	panic("not implemented")
}
func (m *mockConnectionParametersManager) GetHelloMap() (map[handshake.Tag][]byte, error) {
	panic("not implemented")
}
func (m *mockConnectionParametersManager) GetSendStreamFlowControlWindow() protocol.ByteCount {
	return math.MaxUint64
}
func (m *mockConnectionParametersManager) GetSendConnectionFlowControlWindow() protocol.ByteCount {
	return math.MaxUint64
}
func (m *mockConnectionParametersManager) GetReceiveStreamFlowControlWindow() protocol.ByteCount {
	return math.MaxUint64
}
func (m *mockConnectionParametersManager) GetMaxReceiveStreamFlowControlWindow() protocol.ByteCount {
	return math.MaxUint64
}
func (m *mockConnectionParametersManager) GetReceiveConnectionFlowControlWindow() protocol.ByteCount {
	return math.MaxUint64
}
func (m *mockConnectionParametersManager) GetMaxReceiveConnectionFlowControlWindow() protocol.ByteCount {
	return math.MaxUint64
}
func (m *mockConnectionParametersManager) GetMaxOutgoingStreams() uint32 { return m.maxOutgoingStreams }
func (m *mockConnectionParametersManager) GetMaxIncomingStreams() uint32 { return m.maxIncomingStreams }
func (m *mockConnectionParametersManager) GetIdleConnectionStateLifetime() time.Duration {
	return m.idleTime
}
func (m *mockConnectionParametersManager) TruncateConnectionID() bool { return false }

var _ handshake.ConnectionParametersManager = &mockConnectionParametersManager{}

var _ = Describe("Streams Map", func() {
	var (
		cpm handshake.ConnectionParametersManager
		m   *streamsMap
	)

	setNewStreamsMap := func(p protocol.Perspective) {
		m = newStreamsMap(nil, p, cpm)
		m.newStream = func(id protocol.StreamID) (*stream, error) {
			return &stream{streamID: id}, nil
		}
	}

	BeforeEach(func() {
		cpm = &mockConnectionParametersManager{
			maxIncomingStreams: 75,
			maxOutgoingStreams: 60,
		}
	})

	AfterEach(func() {
		Expect(m.openStreams).To(HaveLen(len(m.streams)))
	})

	Context("getting and creating streams", func() {
		Context("as a server", func() {
			BeforeEach(func() {
				setNewStreamsMap(protocol.PerspectiveServer)
			})

			Context("client-side streams", func() {
				It("gets new streams", func() {
					s, err := m.GetOrOpenStream(1)
					Expect(err).NotTo(HaveOccurred())
					Expect(s.StreamID()).To(Equal(protocol.StreamID(1)))
					Expect(m.numIncomingStreams).To(BeEquivalentTo(1))
					Expect(m.numOutgoingStreams).To(BeZero())
				})

				It("rejects streams with even IDs", func() {
					_, err := m.GetOrOpenStream(6)
					Expect(err).To(MatchError("InvalidStreamID: attempted to open stream 6 from client-side"))
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
					s, err := m.GetOrOpenStream(5)
					Expect(err).NotTo(HaveOccurred())
					err = m.RemoveStream(5)
					Expect(err).NotTo(HaveOccurred())
					s, err = m.GetOrOpenStream(5)
					Expect(err).NotTo(HaveOccurred())
					Expect(s).To(BeNil())
				})

				It("opens skipped streams", func() {
					_, err := m.GetOrOpenStream(5)
					Expect(err).NotTo(HaveOccurred())
					Expect(m.streams).To(HaveKey(protocol.StreamID(1)))
					Expect(m.streams).To(HaveKey(protocol.StreamID(3)))
					Expect(m.streams).To(HaveKey(protocol.StreamID(5)))
				})

				It("doesn't reopen an already closed stream", func() {
					_, err := m.GetOrOpenStream(5)
					Expect(err).ToNot(HaveOccurred())
					err = m.RemoveStream(5)
					Expect(err).ToNot(HaveOccurred())
					str, err := m.GetOrOpenStream(5)
					Expect(err).ToNot(HaveOccurred())
					Expect(str).To(BeNil())
				})

				Context("counting streams", func() {
					var maxNumStreams int

					BeforeEach(func() {
						maxNumStreams = int(cpm.GetMaxIncomingStreams())
					})

					It("errors when too many streams are opened", func() {
						for i := 0; i < maxNumStreams; i++ {
							_, err := m.GetOrOpenStream(protocol.StreamID(i*2 + 1))
							Expect(err).NotTo(HaveOccurred())
						}
						_, err := m.GetOrOpenStream(protocol.StreamID(2*maxNumStreams + 2))
						Expect(err).To(MatchError(qerr.TooManyOpenStreams))
					})

					It("errors when too many streams are opened implicitely", func() {
						_, err := m.GetOrOpenStream(protocol.StreamID(maxNumStreams*2 + 1))
						Expect(err).To(MatchError(qerr.TooManyOpenStreams))
					})

					It("does not error when many streams are opened and closed", func() {
						for i := 2; i < 10*maxNumStreams; i++ {
							_, err := m.GetOrOpenStream(protocol.StreamID(i*2 + 1))
							Expect(err).NotTo(HaveOccurred())
							m.RemoveStream(protocol.StreamID(i*2 + 1))
						}
					})
				})
			})

			Context("server-side streams", func() {
				It("opens a stream 2 first", func() {
					s, err := m.OpenStream()
					Expect(err).ToNot(HaveOccurred())
					Expect(s).ToNot(BeNil())
					Expect(s.StreamID()).To(Equal(protocol.StreamID(2)))
					Expect(m.numIncomingStreams).To(BeZero())
					Expect(m.numOutgoingStreams).To(BeEquivalentTo(1))
				})

				Context("counting streams", func() {
					var maxNumStreams int

					BeforeEach(func() {
						maxNumStreams = int(cpm.GetMaxOutgoingStreams())
					})

					It("errors when too many streams are opened", func() {
						for i := 1; i <= maxNumStreams; i++ {
							_, err := m.OpenStream()
							Expect(err).NotTo(HaveOccurred())
						}
						_, err := m.OpenStream()
						Expect(err).To(MatchError(qerr.TooManyOpenStreams))
					})

					It("does not error when many streams are opened and closed", func() {
						for i := 2; i < 10*maxNumStreams; i++ {
							str, err := m.OpenStream()
							Expect(err).NotTo(HaveOccurred())
							m.RemoveStream(str.StreamID())
						}
					})

					It("allows many server- and client-side streams at the same time", func() {
						for i := 1; i < int(cpm.GetMaxOutgoingStreams()); i++ {
							_, err := m.OpenStream()
							Expect(err).ToNot(HaveOccurred())
						}
						for i := 0; i < int(cpm.GetMaxIncomingStreams()); i++ {
							_, err := m.GetOrOpenStream(protocol.StreamID(2*i + 1))
							Expect(err).ToNot(HaveOccurred())
						}
					})
				})
			})
		})

		Context("as a client", func() {
			BeforeEach(func() {
				setNewStreamsMap(protocol.PerspectiveClient)
			})

			Context("client-side streams, as a client", func() {
				It("rejects streams with odd IDs", func() {
					_, err := m.GetOrOpenStream(5)
					Expect(err).To(MatchError("InvalidStreamID: attempted to open stream 5 from server-side"))
				})

				It("gets new streams", func() {
					s, err := m.GetOrOpenStream(2)
					Expect(err).NotTo(HaveOccurred())
					Expect(s.StreamID()).To(Equal(protocol.StreamID(2)))
					Expect(m.numOutgoingStreams).To(BeEquivalentTo(1))
					Expect(m.numIncomingStreams).To(BeZero())
				})

				It("opens skipped streams", func() {
					_, err := m.GetOrOpenStream(6)
					Expect(err).NotTo(HaveOccurred())
					Expect(m.streams).To(HaveKey(protocol.StreamID(2)))
					Expect(m.streams).To(HaveKey(protocol.StreamID(4)))
					Expect(m.streams).To(HaveKey(protocol.StreamID(6)))
				})
			})

			Context("server-side streams", func() {
				It("opens stream 1 first", func() {
					s, err := m.OpenStream()
					Expect(err).ToNot(HaveOccurred())
					Expect(s).ToNot(BeNil())
					Expect(s.StreamID()).To(BeEquivalentTo(1))
					Expect(m.numOutgoingStreams).To(BeZero())
					Expect(m.numIncomingStreams).To(BeEquivalentTo(1))
				})

				It("opens multiple streams", func() {
					s1, err := m.OpenStream()
					Expect(err).ToNot(HaveOccurred())
					s2, err := m.OpenStream()
					Expect(err).ToNot(HaveOccurred())
					Expect(s2.StreamID()).To(Equal(s1.StreamID() + 2))
				})
			})
		})
	})

	Context("DoS mitigation, iterating and deleting", func() {
		BeforeEach(func() {
			setNewStreamsMap(protocol.PerspectiveServer)
		})

		Context("deleting streams", func() {
			BeforeEach(func() {
				for i := 1; i <= 5; i++ {
					err := m.putStream(&stream{streamID: protocol.StreamID(i)})
					Expect(err).ToNot(HaveOccurred())
				}
				Expect(m.openStreams).To(Equal([]protocol.StreamID{1, 2, 3, 4, 5}))
			})

			It("errors when removing non-existing stream", func() {
				err := m.RemoveStream(1337)
				Expect(err).To(MatchError("attempted to remove non-existing stream: 1337"))
			})

			It("removes the first stream", func() {
				err := m.RemoveStream(1)
				Expect(err).ToNot(HaveOccurred())
				Expect(m.openStreams).To(HaveLen(4))
				Expect(m.openStreams).To(Equal([]protocol.StreamID{2, 3, 4, 5}))
			})

			It("removes a stream in the middle", func() {
				err := m.RemoveStream(3)
				Expect(err).ToNot(HaveOccurred())
				Expect(m.openStreams).To(HaveLen(4))
				Expect(m.openStreams).To(Equal([]protocol.StreamID{1, 2, 4, 5}))
			})

			It("removes a stream at the end", func() {
				err := m.RemoveStream(5)
				Expect(err).ToNot(HaveOccurred())
				Expect(m.openStreams).To(HaveLen(4))
				Expect(m.openStreams).To(Equal([]protocol.StreamID{1, 2, 3, 4}))
			})

			It("removes all streams", func() {
				for i := 1; i <= 5; i++ {
					err := m.RemoveStream(protocol.StreamID(i))
					Expect(err).ToNot(HaveOccurred())
				}
				Expect(m.openStreams).To(BeEmpty())
			})
		})

		Context("Iterate", func() {
			// create 3 streams, ids 1 to 3
			BeforeEach(func() {
				for i := 1; i <= 3; i++ {
					err := m.putStream(&stream{streamID: protocol.StreamID(i)})
					Expect(err).NotTo(HaveOccurred())
				}
			})

			It("executes the lambda exactly once for every stream", func() {
				var numIterations int
				callbackCalled := make(map[protocol.StreamID]bool)
				fn := func(str *stream) (bool, error) {
					callbackCalled[str.StreamID()] = true
					numIterations++
					return true, nil
				}
				err := m.Iterate(fn)
				Expect(err).ToNot(HaveOccurred())
				Expect(callbackCalled).To(HaveKey(protocol.StreamID(1)))
				Expect(callbackCalled).To(HaveKey(protocol.StreamID(2)))
				Expect(callbackCalled).To(HaveKey(protocol.StreamID(3)))
				Expect(numIterations).To(Equal(3))
			})

			It("stops iterating when the callback returns false", func() {
				var numIterations int
				fn := func(str *stream) (bool, error) {
					numIterations++
					return false, nil
				}
				err := m.Iterate(fn)
				Expect(err).ToNot(HaveOccurred())
				// due to map access randomization, we don't know for which stream the callback was executed
				// but it must only be executed once
				Expect(numIterations).To(Equal(1))
			})

			It("returns the error, if the lambda returns one", func() {
				var numIterations int
				expectedError := errors.New("test")
				fn := func(str *stream) (bool, error) {
					numIterations++
					return true, expectedError
				}
				err := m.Iterate(fn)
				Expect(err).To(MatchError(expectedError))
				Expect(numIterations).To(Equal(1))
			})
		})

		Context("RoundRobinIterate", func() {
			// create 5 streams, ids 4 to 8
			var lambdaCalledForStream []protocol.StreamID
			var numIterations int

			BeforeEach(func() {
				lambdaCalledForStream = lambdaCalledForStream[:0]
				numIterations = 0
				for i := 4; i <= 8; i++ {
					err := m.putStream(&stream{streamID: protocol.StreamID(i)})
					Expect(err).NotTo(HaveOccurred())
				}
			})

			It("executes the lambda exactly once for every stream", func() {
				fn := func(str *stream) (bool, error) {
					lambdaCalledForStream = append(lambdaCalledForStream, str.StreamID())
					numIterations++
					return true, nil
				}
				err := m.RoundRobinIterate(fn)
				Expect(err).ToNot(HaveOccurred())
				Expect(numIterations).To(Equal(5))
				Expect(lambdaCalledForStream).To(Equal([]protocol.StreamID{4, 5, 6, 7, 8}))
				Expect(m.roundRobinIndex).To(BeZero())
			})

			It("goes around once when starting in the middle", func() {
				fn := func(str *stream) (bool, error) {
					lambdaCalledForStream = append(lambdaCalledForStream, str.StreamID())
					numIterations++
					return true, nil
				}
				m.roundRobinIndex = 3 // pointing to stream 7
				err := m.RoundRobinIterate(fn)
				Expect(err).ToNot(HaveOccurred())
				Expect(numIterations).To(Equal(5))
				Expect(lambdaCalledForStream).To(Equal([]protocol.StreamID{7, 8, 4, 5, 6}))
				Expect(m.roundRobinIndex).To(Equal(uint32(3)))
			})

			It("picks up at the index+1 where it last stopped", func() {
				fn := func(str *stream) (bool, error) {
					lambdaCalledForStream = append(lambdaCalledForStream, str.StreamID())
					numIterations++
					if str.StreamID() == 5 {
						return false, nil
					}
					return true, nil
				}
				err := m.RoundRobinIterate(fn)
				Expect(err).ToNot(HaveOccurred())
				Expect(numIterations).To(Equal(2))
				Expect(lambdaCalledForStream).To(Equal([]protocol.StreamID{4, 5}))
				Expect(m.roundRobinIndex).To(Equal(uint32(2)))
				numIterations = 0
				lambdaCalledForStream = lambdaCalledForStream[:0]
				fn2 := func(str *stream) (bool, error) {
					lambdaCalledForStream = append(lambdaCalledForStream, str.StreamID())
					numIterations++
					if str.StreamID() == 7 {
						return false, nil
					}
					return true, nil
				}
				err = m.RoundRobinIterate(fn2)
				Expect(err).ToNot(HaveOccurred())
				Expect(numIterations).To(Equal(2))
				Expect(lambdaCalledForStream).To(Equal([]protocol.StreamID{6, 7}))
			})

			It("adjust the RoundRobinIndex when deleting an element in front", func() {
				m.roundRobinIndex = 3 // stream 7
				m.RemoveStream(5)
				Expect(m.roundRobinIndex).To(Equal(uint32(2)))
			})

			It("doesn't adjust the RoundRobinIndex when deleting an element at the back", func() {
				m.roundRobinIndex = 1 // stream 5
				m.RemoveStream(7)
				Expect(m.roundRobinIndex).To(BeEquivalentTo(1))
			})

			It("doesn't adjust the RoundRobinIndex when deleting the element it is pointing to", func() {
				m.roundRobinIndex = 3 // stream 7
				m.RemoveStream(7)
				Expect(m.roundRobinIndex).To(Equal(uint32(3)))
			})

			Context("Prioritizing crypto- and header streams", func() {
				BeforeEach(func() {
					err := m.putStream(&stream{streamID: 1})
					Expect(err).NotTo(HaveOccurred())
					err = m.putStream(&stream{streamID: 3})
					Expect(err).NotTo(HaveOccurred())
				})

				It("gets crypto- and header stream first, then picks up at the round-robin position", func() {
					m.roundRobinIndex = 3 // stream 7
					fn := func(str *stream) (bool, error) {
						if numIterations >= 3 {
							return false, nil
						}
						lambdaCalledForStream = append(lambdaCalledForStream, str.StreamID())
						numIterations++
						return true, nil
					}
					err := m.RoundRobinIterate(fn)
					Expect(err).ToNot(HaveOccurred())
					Expect(numIterations).To(Equal(3))
					Expect(lambdaCalledForStream).To(Equal([]protocol.StreamID{1, 3, 7}))
				})
			})
		})
	})
})
