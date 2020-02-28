package quic

import (
	"fmt"
	"io"
	"net"
	"reflect"
	"time"

	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/quictrace"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Config", func() {
	configWithNonZeroNonFunctionFields := func() *Config {
		c := &Config{}
		v := reflect.ValueOf(c).Elem()

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
		return c
	}
	Context("cloning", func() {
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
			c := configWithNonZeroNonFunctionFields()
			Expect(c.Clone()).To(Equal(c))
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

	Context("populating", func() {
		It("populates function fields", func() {
			var calledAcceptToken, calledGetLogWriter bool
			c1 := &Config{
				AcceptToken:  func(_ net.Addr, _ *Token) bool { calledAcceptToken = true; return true },
				GetLogWriter: func(connectionID []byte) io.WriteCloser { calledGetLogWriter = true; return nil },
			}
			c2 := populateConfig(c1)
			c2.AcceptToken(&net.UDPAddr{}, &Token{})
			c2.GetLogWriter([]byte{1, 2, 3})
			Expect(calledAcceptToken).To(BeTrue())
			Expect(calledGetLogWriter).To(BeTrue())
		})

		It("copies non-function fields", func() {
			c := configWithNonZeroNonFunctionFields()
			Expect(populateConfig(c)).To(Equal(c))
		})

		It("populates empty fields with default values", func() {
			c := populateConfig(&Config{})
			Expect(c.Versions).To(Equal(protocol.SupportedVersions))
			Expect(c.HandshakeTimeout).To(Equal(protocol.DefaultHandshakeTimeout))
			Expect(c.MaxReceiveStreamFlowControlWindow).To(BeEquivalentTo(protocol.DefaultMaxReceiveStreamFlowControlWindow))
			Expect(c.MaxReceiveConnectionFlowControlWindow).To(BeEquivalentTo(protocol.DefaultMaxReceiveConnectionFlowControlWindow))
			Expect(c.MaxIncomingStreams).To(Equal(protocol.DefaultMaxIncomingStreams))
			Expect(c.MaxIncomingUniStreams).To(Equal(protocol.DefaultMaxIncomingUniStreams))
		})

		It("populates empty fields with default values, for the server", func() {
			c := populateServerConfig(&Config{})
			Expect(c.ConnectionIDLength).To(Equal(protocol.DefaultConnectionIDLength))
			Expect(c.AcceptToken).ToNot(BeNil())
		})

		It("sets a default connection ID length if we didn't create the conn, for the client", func() {
			c := populateClientConfig(&Config{}, false)
			Expect(c.ConnectionIDLength).To(Equal(protocol.DefaultConnectionIDLength))
		})

		It("doesn't set a default connection ID length if we created the conn, for the client", func() {
			c := populateClientConfig(&Config{}, true)
			Expect(c.ConnectionIDLength).To(BeZero())
		})
	})
})
