package quic

import (
	"errors"
	"io"
	"os"
	"runtime"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/lucas-clemente/quic-go/crypto"
	"github.com/lucas-clemente/quic-go/frames"
	"github.com/lucas-clemente/quic-go/handshake"
	"github.com/lucas-clemente/quic-go/protocol"
	"github.com/lucas-clemente/quic-go/utils"
)

type mockConnection struct {
	written [][]byte
}

func (m *mockConnection) write(p []byte) error {
	m.written = append(m.written, p)
	return nil
}

func (*mockConnection) setCurrentRemoteAddr(addr interface{}) {}

var _ = Describe("Session", func() {
	var (
		session        *Session
		callbackCalled bool
		conn           *mockConnection
	)

	BeforeEach(func() {
		conn = &mockConnection{}
		callbackCalled = false
		session = &Session{
			conn:           conn,
			streams:        make(map[protocol.StreamID]*stream),
			streamCallback: func(*Session, utils.Stream) { callbackCalled = true },
		}
	})

	Context("when handling stream frames", func() {
		It("makes new streams", func() {
			session.handleStreamFrame(&frames.StreamFrame{
				StreamID: 5,
				Data:     []byte{0xde, 0xca, 0xfb, 0xad},
			})
			Expect(session.streams).To(HaveLen(1))
			Expect(callbackCalled).To(BeTrue())
			p := make([]byte, 4)
			_, err := session.streams[5].Read(p)
			Expect(err).ToNot(HaveOccurred())
			Expect(p).To(Equal([]byte{0xde, 0xca, 0xfb, 0xad}))
		})

		It("handles existing streams", func() {
			session.handleStreamFrame(&frames.StreamFrame{
				StreamID: 5,
				Data:     []byte{0xde, 0xca},
			})
			Expect(session.streams).To(HaveLen(1))
			Expect(callbackCalled).To(BeTrue())
			session.handleStreamFrame(&frames.StreamFrame{
				StreamID: 5,
				Offset:   2,
				Data:     []byte{0xfb, 0xad},
			})
			Expect(session.streams).To(HaveLen(1))
			p := make([]byte, 4)
			_, err := session.streams[5].Read(p)
			Expect(err).ToNot(HaveOccurred())
			Expect(p).To(Equal([]byte{0xde, 0xca, 0xfb, 0xad}))
		})

		It("closes streams with FIN bits", func() {
			session.handleStreamFrame(&frames.StreamFrame{
				StreamID: 5,
				Data:     []byte{0xde, 0xca, 0xfb, 0xad},
				FinBit:   true,
			})
			Expect(session.streams).To(HaveLen(1))
			Expect(session.streams[5]).ToNot(BeNil())
			Expect(callbackCalled).To(BeTrue())
			p := make([]byte, 4)
			_, err := session.streams[5].Read(p)
			Expect(err).To(Equal(io.EOF))
			Expect(p).To(Equal([]byte{0xde, 0xca, 0xfb, 0xad}))
			session.garbageCollectStreams()
			Expect(session.streams).To(HaveLen(1))
			Expect(session.streams[5]).To(BeNil())
		})

		It("closes streams with error", func() {
			testErr := errors.New("test")
			session.handleStreamFrame(&frames.StreamFrame{
				StreamID: 5,
				Data:     []byte{0xde, 0xca, 0xfb, 0xad},
			})
			Expect(session.streams).To(HaveLen(1))
			Expect(session.streams[5]).ToNot(BeNil())
			Expect(callbackCalled).To(BeTrue())
			p := make([]byte, 4)
			_, err := session.streams[5].Read(p)
			Expect(err).ToNot(HaveOccurred())
			session.closeStreamsWithError(testErr)
			_, err = session.streams[5].Read(p)
			Expect(err).To(Equal(testErr))
			session.garbageCollectStreams()
			Expect(session.streams).To(HaveLen(1))
			Expect(session.streams[5]).To(BeNil())
		})

		It("closes empty streams with error", func() {
			testErr := errors.New("test")
			session.handleStreamFrame(&frames.StreamFrame{
				StreamID: 5,
			})
			Expect(session.streams).To(HaveLen(1))
			Expect(session.streams[5]).ToNot(BeNil())
			Expect(callbackCalled).To(BeTrue())
			session.closeStreamsWithError(testErr)
			_, err := session.streams[5].Read([]byte{0})
			Expect(err).To(Equal(testErr))
			session.garbageCollectStreams()
			Expect(session.streams).To(HaveLen(1))
			Expect(session.streams[5]).To(BeNil())
		})

		It("rejects streams that existed previously", func() {
			session.handleStreamFrame(&frames.StreamFrame{
				StreamID: 5,
				Data:     []byte{},
				FinBit:   true,
			})
			_, err := session.streams[5].Read([]byte{0})
			Expect(err).To(Equal(io.EOF))
			session.garbageCollectStreams()
			err = session.handleStreamFrame(&frames.StreamFrame{
				StreamID: 5,
				Data:     []byte{},
			})
			Expect(err).To(MatchError("Session: reopening streams is not allowed"))
		})
	})

	Context("handling RST_STREAM frames", func() {
		It("closes the receiving streams for writing and reading", func() {
			s, err := session.NewStream(5)
			Expect(err).ToNot(HaveOccurred())
			err = session.handleRstStreamFrame(&frames.RstStreamFrame{
				StreamID:  5,
				ErrorCode: 42,
			})
			Expect(err).ToNot(HaveOccurred())
			n, err := s.Write([]byte{0})
			Expect(n).To(BeZero())
			Expect(err).To(MatchError("RST_STREAM received with code 42"))
			n, err = s.Read([]byte{0})
			Expect(n).To(BeZero())
			Expect(err).To(MatchError("RST_STREAM received with code 42"))
		})

		It("errors when the stream is not known", func() {
			err := session.handleRstStreamFrame(&frames.RstStreamFrame{
				StreamID:  5,
				ErrorCode: 42,
			})
			Expect(err).To(MatchError("RST_STREAM received for unknown stream"))
		})
	})

	Context("closing", func() {
		var (
			nGoRoutinesBefore int
		)

		BeforeEach(func() {
			time.Sleep(1 * time.Millisecond) // Wait for old goroutines to finish
			nGoRoutinesBefore = runtime.NumGoroutine()
			path := os.Getenv("GOPATH") + "/src/github.com/lucas-clemente/quic-go/example/"
			signer, err := crypto.NewRSASigner(path+"cert.der", path+"key.der")
			Expect(err).ToNot(HaveOccurred())
			scfg := handshake.NewServerConfig(crypto.NewCurve25519KEX(), signer)
			session = NewSession(conn, 0, 0, scfg, nil).(*Session)
			go session.Run()
			Expect(runtime.NumGoroutine()).To(Equal(nGoRoutinesBefore + 2))
		})

		It("shuts down without error", func() {
			session.Close(nil)
			time.Sleep(1 * time.Millisecond)
			Expect(runtime.NumGoroutine()).To(Equal(nGoRoutinesBefore))
		})

		It("closes streams with proper error", func() {
			testErr := errors.New("test error")
			s, err := session.NewStream(5)
			Expect(err).NotTo(HaveOccurred())
			session.Close(testErr)
			time.Sleep(1 * time.Millisecond)
			Expect(runtime.NumGoroutine()).To(Equal(nGoRoutinesBefore))
			n, err := s.Read([]byte{0})
			Expect(n).To(BeZero())
			Expect(err).To(Equal(testErr))
			n, err = s.Write([]byte{0})
			Expect(n).To(BeZero())
			Expect(err).To(Equal(testErr))
		})
	})

	Context("sending packets", func() {
		BeforeEach(func() {
			path := os.Getenv("GOPATH") + "/src/github.com/lucas-clemente/quic-go/example/"
			signer, err := crypto.NewRSASigner(path+"cert.der", path+"key.der")
			Expect(err).ToNot(HaveOccurred())
			scfg := handshake.NewServerConfig(crypto.NewCurve25519KEX(), signer)
			session = NewSession(conn, 0, 0, scfg, nil).(*Session)
		})

		It("sends ack frames", func() {
			session.receivedPacketHandler.ReceivedPacket(1, true)
			err := session.sendPacket()
			Expect(err).NotTo(HaveOccurred())
			Expect(conn.written).To(HaveLen(1))
			Expect(conn.written[0]).To(ContainSubstring(string([]byte{0x4c, 0x2, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1, 0x0, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0})))
		})

		It("sends queued stream frames", func() {
			session.QueueStreamFrame(&frames.StreamFrame{
				StreamID: 1,
				Data:     []byte("foobar"),
			})
			session.receivedPacketHandler.ReceivedPacket(1, true)
			err := session.sendPacket()
			Expect(err).NotTo(HaveOccurred())
			Expect(conn.written).To(HaveLen(1))
			Expect(conn.written[0]).To(ContainSubstring(string([]byte{0x4c, 0x2, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1, 0x0, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0})))
			Expect(conn.written[0]).To(ContainSubstring(string("foobar")))
		})
	})
})
