package quic

import (
	"fmt"
	"io"
	"net"
	"reflect"
	"time"

	"github.com/lucas-clemente/quic-go/quictrace"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Config", func() {
	It("clones function fields", func() {
		var calledAcceptToken, calledGetLogWriter bool
		c1 := &Config{
			AcceptToken:  func(_ net.Addr, _ *Token) bool { calledAcceptToken = true; return true },
			GetLogWriter: func(connectionID []byte) io.WriteCloser { calledGetLogWriter = true; return nil },
		}
		c2 := c1.Clone()
		c2.AcceptToken(&net.UDPAddr{}, &Token{})
		c2.GetLogWriter([]byte{1, 2, 3})
		Expect(calledAcceptToken).To(BeTrue())
		Expect(calledGetLogWriter).To(BeTrue())
	})

	It("clones non-function fields", func() {
		c1 := &Config{}
		v := reflect.ValueOf(c1).Elem()

		typ := v.Type()
		for i := 0; i < typ.NumField(); i++ {
			f := v.Field(i)
			if !f.CanSet() {
				// unexported field; not cloned.
				continue
			}

			switch fn := typ.Field(i).Name; fn {
			case "AcceptToken", "GetLogWriter":
				// Can't compare functions.
			case "Versions":
				f.Set(reflect.ValueOf([]VersionNumber{1, 2, 3}))
			case "ConnectionIDLength":
				f.Set(reflect.ValueOf(8))
			case "HandshakeTimeout":
				f.Set(reflect.ValueOf(time.Second))
			case "MaxIdleTimeout":
				f.Set(reflect.ValueOf(time.Hour))
			case "TokenStore":
				f.Set(reflect.ValueOf(NewLRUTokenStore(2, 3)))
			case "MaxReceiveStreamFlowControlWindow":
				f.Set(reflect.ValueOf(uint64(9)))
			case "MaxReceiveConnectionFlowControlWindow":
				f.Set(reflect.ValueOf(uint64(10)))
			case "MaxIncomingStreams":
				f.Set(reflect.ValueOf(11))
			case "MaxIncomingUniStreams":
				f.Set(reflect.ValueOf(12))
			case "StatelessResetKey":
				f.Set(reflect.ValueOf([]byte{1, 2, 3, 4}))
			case "KeepAlive":
				f.Set(reflect.ValueOf(true))
			case "QuicTracer":
				f.Set(reflect.ValueOf(quictrace.NewTracer()))
			default:
				Fail(fmt.Sprintf("all fields must be accounted for, but saw unknown field %q", fn))
			}
		}

		Expect(c1.Clone()).To(Equal(c1))
	})

	It("returns a copy", func() {
		c1 := &Config{
			MaxIncomingStreams: 100,
			AcceptToken:        func(_ net.Addr, _ *Token) bool { return true },
		}
		c2 := c1.Clone()
		c2.MaxIncomingStreams = 200
		c2.AcceptToken = func(_ net.Addr, _ *Token) bool { return false }

		Expect(c1.MaxIncomingStreams).To(BeEquivalentTo(100))
		Expect(c1.AcceptToken(&net.UDPAddr{}, nil)).To(BeTrue())
	})
})
