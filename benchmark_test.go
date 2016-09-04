package quic

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	mrand "math/rand"
	"net"
	"reflect"
	"time"
	"unsafe"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/lucas-clemente/quic-go/crypto"
	"github.com/lucas-clemente/quic-go/handshake"
	"github.com/lucas-clemente/quic-go/protocol"
	"github.com/lucas-clemente/quic-go/utils"
)

type linkedConnection struct {
	other *Session
	c     chan []byte
}

func newLinkedConnection(other *Session) *linkedConnection {
	c := make(chan []byte, 500)
	conn := &linkedConnection{
		c:     c,
		other: other,
	}
	go func() {
		for packet := range c {
			r := bytes.NewReader(packet)
			hdr, err := ParsePublicHeader(r)
			if err != nil {
				Expect(err).NotTo(HaveOccurred())
			}
			hdr.Raw = packet[:len(packet)-r.Len()]
			conn.other.handlePacket(nil, hdr, packet[len(packet)-r.Len():])
		}
	}()
	return conn
}

func (c *linkedConnection) write(p []byte) error {
	packet := getPacketBuffer()
	packet = packet[:len(p)]
	copy(packet, p)
	select {
	case c.c <- packet:
	default:
	}
	return nil
}

func (*linkedConnection) setCurrentRemoteAddr(addr interface{}) {}
func (*linkedConnection) RemoteAddr() *net.UDPAddr              { return &net.UDPAddr{} }

func setAEAD(cs *handshake.CryptoSetup, aead crypto.AEAD) {
	*(*bool)(unsafe.Pointer(reflect.ValueOf(cs).Elem().FieldByName("receivedForwardSecurePacket").UnsafeAddr())) = true
	*(*crypto.AEAD)(unsafe.Pointer(reflect.ValueOf(cs).Elem().FieldByName("forwardSecureAEAD").UnsafeAddr())) = aead
}

func setFlowControlParameters(mgr *handshake.ConnectionParametersManager) {
	sfcw := make([]byte, 4)
	cfcw := make([]byte, 4)
	binary.LittleEndian.PutUint32(sfcw, uint32(protocol.ReceiveStreamFlowControlWindow))
	binary.LittleEndian.PutUint32(cfcw, uint32(protocol.ReceiveConnectionFlowControlWindow))
	mgr.SetFromMap(map[handshake.Tag][]byte{
		handshake.TagSFCW: sfcw,
		handshake.TagCFCW: cfcw,
	})
}

var _ = Describe("Benchmarks", func() {
	for i := range protocol.SupportedVersions {
		version := protocol.SupportedVersions[i]

		Context(fmt.Sprintf("with version %d", version), func() {
			dataLen := 50 /* MB */ * (1 << 20)
			data := make([]byte, dataLen)

			Measure("two linked sessions", func(b Benchmarker) {
				connID := protocol.ConnectionID(mrand.Uint32())

				c1 := newLinkedConnection(nil)
				session1I, err := newSession(c1, version, connID, nil, func(*Session, utils.Stream) {}, func(id protocol.ConnectionID) {})
				if err != nil {
					Expect(err).NotTo(HaveOccurred())
				}
				session1 := session1I.(*Session)

				c2 := newLinkedConnection(session1)
				session2I, err := newSession(c2, version, connID, nil, func(*Session, utils.Stream) {}, func(id protocol.ConnectionID) {})
				if err != nil {
					Expect(err).NotTo(HaveOccurred())
				}
				session2 := session2I.(*Session)
				c1.other = session2

				key := make([]byte, 16)
				iv := make([]byte, 4)
				rand.Read(key)
				rand.Read(iv)
				aead, err := crypto.NewAEADAESGCM(key, key, iv, iv)
				Expect(err).NotTo(HaveOccurred())
				setAEAD(session1.cryptoSetup, aead)
				setAEAD(session2.cryptoSetup, aead)

				setFlowControlParameters(session1.connectionParametersManager)
				setFlowControlParameters(session2.connectionParametersManager)

				go session1.run()
				go session2.run()

				s1stream, err := session1.GetOrOpenStream(5)
				Expect(err).NotTo(HaveOccurred())
				s2stream, err := session2.GetOrOpenStream(5)
				Expect(err).NotTo(HaveOccurred())

				done := make(chan struct{})
				go func() {
					defer GinkgoRecover()
					buf := make([]byte, 1024)
					dataRead := 0
					for dataRead < dataLen {
						n, err := s2stream.Read(buf)
						Expect(err).NotTo(HaveOccurred())
						dataRead += n
					}
					done <- struct{}{}
				}()

				time.Sleep(time.Millisecond)
				runtime := b.Time("transfer time", func() {
					_, err := io.Copy(s1stream, bytes.NewReader(data))
					Expect(err).NotTo(HaveOccurred())
					<-done
				})

				session1.Close(nil)
				session2.Close(nil)
				time.Sleep(time.Millisecond)

				b.RecordValue("transfer rate [MB/s]", float64(dataLen)/1e6/runtime.Seconds())
			}, 3)
		})
	}
})
