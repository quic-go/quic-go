package quic

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/logging"
	"github.com/quic-go/quic-go/quicvarint"

	"github.com/stretchr/testify/require"
)

func TestConfigValidation(t *testing.T) {
	t.Run("nil config", func(t *testing.T) {
		require.NoError(t, validateConfig(nil))
	})

	t.Run("config with a few values set", func(t *testing.T) {
		conf := populateConfig(&Config{
			MaxIncomingStreams:     5,
			MaxStreamReceiveWindow: 10,
		})
		require.NoError(t, validateConfig(conf))
		require.Equal(t, int64(5), conf.MaxIncomingStreams)
		require.Equal(t, uint64(10), conf.MaxStreamReceiveWindow)
	})

	t.Run("stream limits", func(t *testing.T) {
		conf := &Config{
			MaxIncomingStreams:    1<<60 + 1,
			MaxIncomingUniStreams: 1<<60 + 2,
		}
		require.NoError(t, validateConfig(conf))
		require.Equal(t, int64(1<<60), conf.MaxIncomingStreams)
		require.Equal(t, int64(1<<60), conf.MaxIncomingUniStreams)
	})

	t.Run("flow control windows", func(t *testing.T) {
		conf := &Config{
			MaxStreamReceiveWindow:     quicvarint.Max + 1,
			MaxConnectionReceiveWindow: quicvarint.Max + 2,
		}
		require.NoError(t, validateConfig(conf))
		require.Equal(t, uint64(quicvarint.Max), conf.MaxStreamReceiveWindow)
		require.Equal(t, uint64(quicvarint.Max), conf.MaxConnectionReceiveWindow)
	})

	t.Run("initial packet size", func(t *testing.T) {
		// not set
		conf := &Config{InitialPacketSize: 0}
		require.NoError(t, validateConfig(conf))
		require.Zero(t, conf.InitialPacketSize)

		// too small
		conf = &Config{InitialPacketSize: 10}
		require.NoError(t, validateConfig(conf))
		require.Equal(t, uint16(1200), conf.InitialPacketSize)

		// too large
		conf = &Config{InitialPacketSize: protocol.MaxPacketBufferSize + 1}
		require.NoError(t, validateConfig(conf))
		require.Equal(t, uint16(protocol.MaxPacketBufferSize), conf.InitialPacketSize)
	})
}

func TestConfigHandshakeIdleTimeout(t *testing.T) {
	c := &Config{HandshakeIdleTimeout: time.Second * 11 / 2}
	require.Equal(t, 11*time.Second, c.handshakeTimeout())
}

func configWithNonZeroNonFunctionFields(t *testing.T) *Config {
	t.Helper()
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
		case "InitialPacketSize":
			f.Set(reflect.ValueOf(uint16(1350)))
		case "DisablePathMTUDiscovery":
			f.Set(reflect.ValueOf(true))
		case "Allow0RTT":
			f.Set(reflect.ValueOf(true))
		default:
			t.Fatalf("all fields must be accounted for, but saw unknown field %q", fn)
		}
	}
	return c
}

func TestConfigCloning(t *testing.T) {
	t.Run("function fields", func(t *testing.T) {
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
		require.True(t, calledAllowConnectionWindowIncrease)
		_, err := c2.GetConfigForClient(&ClientHelloInfo{})
		require.EqualError(t, err, "nope")
		c2.Tracer(context.Background(), logging.PerspectiveClient, protocol.ConnectionID{})
		require.True(t, calledTracer)
	})

	t.Run("clones non-function fields", func(t *testing.T) {
		c := configWithNonZeroNonFunctionFields(t)
		require.Equal(t, c, c.Clone())
	})

	t.Run("returns a copy", func(t *testing.T) {
		c1 := &Config{MaxIncomingStreams: 100}
		c2 := c1.Clone()
		c2.MaxIncomingStreams = 200
		require.EqualValues(t, 100, c1.MaxIncomingStreams)
	})
}

func TestConfigDefaultValues(t *testing.T) {
	// if set, the values should be copied
	c := configWithNonZeroNonFunctionFields(t)
	require.Equal(t, c, populateConfig(c))

	// if not set, some fields use default values
	c = populateConfig(&Config{})
	require.Equal(t, protocol.SupportedVersions, c.Versions)
	require.Equal(t, protocol.DefaultHandshakeIdleTimeout, c.HandshakeIdleTimeout)
	require.Equal(t, protocol.DefaultIdleTimeout, c.MaxIdleTimeout)
	require.EqualValues(t, protocol.DefaultInitialMaxStreamData, c.InitialStreamReceiveWindow)
	require.EqualValues(t, protocol.DefaultMaxReceiveStreamFlowControlWindow, c.MaxStreamReceiveWindow)
	require.EqualValues(t, protocol.DefaultInitialMaxData, c.InitialConnectionReceiveWindow)
	require.EqualValues(t, protocol.DefaultMaxReceiveConnectionFlowControlWindow, c.MaxConnectionReceiveWindow)
	require.EqualValues(t, protocol.DefaultMaxIncomingStreams, c.MaxIncomingStreams)
	require.EqualValues(t, protocol.DefaultMaxIncomingUniStreams, c.MaxIncomingUniStreams)
	require.False(t, c.DisablePathMTUDiscovery)
	require.Nil(t, c.GetConfigForClient)
}

func TestConfigZeroLimits(t *testing.T) {
	config := &Config{
		MaxIncomingStreams:    -1,
		MaxIncomingUniStreams: -1,
	}
	c := populateConfig(config)
	require.Zero(t, c.MaxIncomingStreams)
	require.Zero(t, c.MaxIncomingUniStreams)
}
