package quic

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"time"

	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/logging"
	"github.com/quic-go/quic-go/quicvarint"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Config", func() {
	Context("validating", func() {
		It("validates a nil config", func() {
			Expect(validateConfig(nil)).To(Succeed())
		})

		It("validates a config with normal values", func() {
			conf := populateConfig(&Config{
				MaxIncomingStreams:     5,
				MaxStreamReceiveWindow: 10,
			})
			Expect(validateConfig(conf)).To(Succeed())
			Expect(conf.MaxIncomingStreams).To(BeEquivalentTo(5))
			Expect(conf.MaxStreamReceiveWindow).To(BeEquivalentTo(10))
		})

		It("clips too large values for the stream limits", func() {
			conf := &Config{
				MaxIncomingStreams:    1<<60 + 1,
				MaxIncomingUniStreams: 1<<60 + 2,
			}
			Expect(validateConfig(conf)).To(Succeed())
			Expect(conf.MaxIncomingStreams).To(BeEquivalentTo(int64(1 << 60)))
			Expect(conf.MaxIncomingUniStreams).To(BeEquivalentTo(int64(1 << 60)))
		})

		It("clips too large values for the flow control windows", func() {
			conf := &Config{
				MaxStreamReceiveWindow:     quicvarint.Max + 1,
				MaxConnectionReceiveWindow: quicvarint.Max + 2,
			}
			Expect(validateConfig(conf)).To(Succeed())
			Expect(conf.MaxStreamReceiveWindow).To(BeEquivalentTo(uint64(quicvarint.Max)))
			Expect(conf.MaxConnectionReceiveWindow).To(BeEquivalentTo(uint64(quicvarint.Max)))
		})
	})

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
			case "GetConfigForClient", "RequireAddressValidation", "GetLogWriter", "AllowConnectionWindowIncrease", "Tracer":
				// Can't compare functions.
			case "Versions":
				f.Set(reflect.ValueOf([]Version{1, 2, 3}))
			case "ConnectionIDLength":
				f.Set(reflect.ValueOf(8))
			case "ConnectionIDGenerator":
				f.Set(reflect.ValueOf(&protocol.DefaultConnectionIDGenerator{ConnLen: protocol.DefaultConnectionIDLength}))
			case "HandshakeIdleTimeout":
				f.Set(reflect.ValueOf(time.Second))
			case "MaxIdleTimeout":
				f.Set(reflect.ValueOf(time.Hour))
			case "TokenStore":
				f.Set(reflect.ValueOf(NewLRUTokenStore(2, 3)))
			case "InitialStreamReceiveWindow":
				f.Set(reflect.ValueOf(uint64(1234)))
			case "MaxStreamReceiveWindow":
				f.Set(reflect.ValueOf(uint64(9)))
			case "InitialConnectionReceiveWindow":
				f.Set(reflect.ValueOf(uint64(4321)))
			case "MaxConnectionReceiveWindow":
				f.Set(reflect.ValueOf(uint64(10)))
			case "MaxIncomingStreams":
				f.Set(reflect.ValueOf(int64(11)))
			case "MaxIncomingUniStreams":
				f.Set(reflect.ValueOf(int64(12)))
			case "StatelessResetKey":
				f.Set(reflect.ValueOf(&StatelessResetKey{1, 2, 3, 4}))
			case "KeepAlivePeriod":
				f.Set(reflect.ValueOf(time.Second))
			case "EnableDatagrams":
				f.Set(reflect.ValueOf(true))
			case "DisableVersionNegotiationPackets":
				f.Set(reflect.ValueOf(true))
			case "DisablePathMTUDiscovery":
				f.Set(reflect.ValueOf(true))
			case "Allow0RTT":
				f.Set(reflect.ValueOf(true))
			default:
				Fail(fmt.Sprintf("all fields must be accounted for, but saw unknown field %q", fn))
			}
		}
		return c
	}

	It("uses twice the handshake idle timeouts for the handshake timeout", func() {
		c := &Config{HandshakeIdleTimeout: time.Second * 11 / 2}
		Expect(c.handshakeTimeout()).To(Equal(11 * time.Second))
	})

	Context("cloning", func() {
		It("clones function fields", func() {
			var calledAllowConnectionWindowIncrease, calledTracer bool
			c1 := &Config{
				GetConfigForClient:            func(info *ClientHelloInfo) (*Config, error) { return nil, errors.New("nope") },
				AllowConnectionWindowIncrease: func(Connection, uint64) bool { calledAllowConnectionWindowIncrease = true; return true },
				Tracer: func(context.Context, logging.Perspective, ConnectionID) *logging.ConnectionTracer {
					calledTracer = true
					return nil
				},
			}
			c2 := c1.Clone()
			c2.AllowConnectionWindowIncrease(nil, 1234)
			Expect(calledAllowConnectionWindowIncrease).To(BeTrue())
			_, err := c2.GetConfigForClient(&ClientHelloInfo{})
			Expect(err).To(MatchError("nope"))
			c2.Tracer(context.Background(), logging.PerspectiveClient, protocol.ConnectionID{})
			Expect(calledTracer).To(BeTrue())
		})

		It("clones non-function fields", func() {
			c := configWithNonZeroNonFunctionFields()
			Expect(c.Clone()).To(Equal(c))
		})

		It("returns a copy", func() {
			c1 := &Config{MaxIncomingStreams: 100}
			c2 := c1.Clone()
			c2.MaxIncomingStreams = 200

			Expect(c1.MaxIncomingStreams).To(BeEquivalentTo(100))
		})
	})

	Context("populating", func() {
		It("copies non-function fields", func() {
			c := configWithNonZeroNonFunctionFields()
			Expect(populateConfig(c)).To(Equal(c))
		})

		It("populates empty fields with default values", func() {
			c := populateConfig(&Config{})
			Expect(c.Versions).To(Equal(protocol.SupportedVersions))
			Expect(c.HandshakeIdleTimeout).To(Equal(protocol.DefaultHandshakeIdleTimeout))
			Expect(c.InitialStreamReceiveWindow).To(BeEquivalentTo(protocol.DefaultInitialMaxStreamData))
			Expect(c.MaxStreamReceiveWindow).To(BeEquivalentTo(protocol.DefaultMaxReceiveStreamFlowControlWindow))
			Expect(c.InitialConnectionReceiveWindow).To(BeEquivalentTo(protocol.DefaultInitialMaxData))
			Expect(c.MaxConnectionReceiveWindow).To(BeEquivalentTo(protocol.DefaultMaxReceiveConnectionFlowControlWindow))
			Expect(c.MaxIncomingStreams).To(BeEquivalentTo(protocol.DefaultMaxIncomingStreams))
			Expect(c.MaxIncomingUniStreams).To(BeEquivalentTo(protocol.DefaultMaxIncomingUniStreams))
			Expect(c.DisablePathMTUDiscovery).To(BeFalse())
			Expect(c.GetConfigForClient).To(BeNil())
		})
	})
})
