package qtls

import (
	"crypto/tls"
	"net"
	"reflect"
	"testing"

	"github.com/quic-go/quic-go/internal/protocol"

	"github.com/stretchr/testify/require"
)

func TestEncryptionLevelConversion(t *testing.T) {
	testCases := []struct {
		quicLevel protocol.EncryptionLevel
		tlsLevel  tls.QUICEncryptionLevel
	}{
		{protocol.EncryptionInitial, tls.QUICEncryptionLevelInitial},
		{protocol.EncryptionHandshake, tls.QUICEncryptionLevelHandshake},
		{protocol.Encryption1RTT, tls.QUICEncryptionLevelApplication},
		{protocol.Encryption0RTT, tls.QUICEncryptionLevelEarly},
	}

	for _, tc := range testCases {
		t.Run(tc.quicLevel.String(), func(t *testing.T) {
			// conversion from QUIC to TLS encryption level
			require.Equal(t, tc.tlsLevel, ToTLSEncryptionLevel(tc.quicLevel))
			// conversion from TLS to QUIC encryption level
			require.Equal(t, tc.quicLevel, FromTLSEncryptionLevel(tc.tlsLevel))
		})
	}
}

func TestSetupSessionCache(t *testing.T) {
	// Test with a session cache present
	csc := tls.NewLRUClientSessionCache(1)
	confWithCache := &tls.QUICConfig{TLSConfig: &tls.Config{ClientSessionCache: csc}}
	SetupConfigForClient(confWithCache, nil, nil)
	require.NotNil(t, confWithCache.TLSConfig.ClientSessionCache)
	require.NotEqual(t, csc, confWithCache.TLSConfig.ClientSessionCache)

	// Test without a session cache
	confWithoutCache := &tls.QUICConfig{TLSConfig: &tls.Config{}}
	SetupConfigForClient(confWithoutCache, nil, nil)
	require.Nil(t, confWithoutCache.TLSConfig.ClientSessionCache)
}

func TestMinimumTLSVersion(t *testing.T) {
	local := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 42}
	remote := &net.UDPAddr{IP: net.IPv4(192, 168, 0, 1), Port: 1337}

	orig := &tls.Config{MinVersion: tls.VersionTLS12}
	conf := SetupConfigForServer(orig, local, remote, nil, nil)
	require.EqualValues(t, tls.VersionTLS13, conf.MinVersion)
	// check that the original config wasn't modified
	require.EqualValues(t, tls.VersionTLS12, orig.MinVersion)
}

func TestServerConfigGetCertificate(t *testing.T) {
	local := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 42}
	remote := &net.UDPAddr{IP: net.IPv4(192, 168, 0, 1), Port: 1337}

	var localAddr, remoteAddr net.Addr
	tlsConf := &tls.Config{
		GetCertificate: func(info *tls.ClientHelloInfo) (*tls.Certificate, error) {
			localAddr = info.Conn.LocalAddr()
			remoteAddr = info.Conn.RemoteAddr()
			return &tls.Certificate{}, nil
		},
	}
	conf := SetupConfigForServer(tlsConf, local, remote, nil, nil)
	_, err := conf.GetCertificate(&tls.ClientHelloInfo{})
	require.NoError(t, err)
	require.Equal(t, local, localAddr)
	require.Equal(t, remote, remoteAddr)
}

func TestServerConfigGetConfigForClient(t *testing.T) {
	local := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 42}
	remote := &net.UDPAddr{IP: net.IPv4(192, 168, 0, 1), Port: 1337}

	var localAddr, remoteAddr net.Addr
	tlsConf := SetupConfigForServer(
		&tls.Config{
			GetConfigForClient: func(info *tls.ClientHelloInfo) (*tls.Config, error) {
				localAddr = info.Conn.LocalAddr()
				remoteAddr = info.Conn.RemoteAddr()
				return &tls.Config{}, nil
			},
		},
		local,
		remote,
		nil,
		nil,
	)
	conf, err := tlsConf.GetConfigForClient(&tls.ClientHelloInfo{})
	require.NoError(t, err)
	require.Equal(t, local, localAddr)
	require.Equal(t, remote, remoteAddr)
	require.NotNil(t, conf)
	require.EqualValues(t, tls.VersionTLS13, conf.MinVersion)
}

func TestServerConfigGetConfigForClientRecursively(t *testing.T) {
	local := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 42}
	remote := &net.UDPAddr{IP: net.IPv4(192, 168, 0, 1), Port: 1337}

	var localAddr, remoteAddr net.Addr
	tlsConf := &tls.Config{}
	var innerConf *tls.Config
	getCert := func(info *tls.ClientHelloInfo) (*tls.Certificate, error) {
		localAddr = info.Conn.LocalAddr()
		remoteAddr = info.Conn.RemoteAddr()
		return &tls.Certificate{}, nil
	}
	tlsConf.GetConfigForClient = func(info *tls.ClientHelloInfo) (*tls.Config, error) {
		innerConf = tlsConf.Clone()
		// set the MaxVersion, so we can check that quic-go doesn't overwrite the user's config
		innerConf.MaxVersion = tls.VersionTLS12
		innerConf.GetCertificate = getCert
		return innerConf, nil
	}
	tlsConf = SetupConfigForServer(tlsConf, local, remote, nil, nil)
	conf, err := tlsConf.GetConfigForClient(&tls.ClientHelloInfo{})
	require.NoError(t, err)
	require.NotNil(t, conf)
	require.EqualValues(t, tls.VersionTLS13, conf.MinVersion)
	_, err = conf.GetCertificate(&tls.ClientHelloInfo{})
	require.NoError(t, err)
	require.Equal(t, local, localAddr)
	require.Equal(t, remote, remoteAddr)
	// make sure that the tls.Config returned by GetConfigForClient isn't modified
	require.True(t, reflect.ValueOf(innerConf.GetCertificate).Pointer() == reflect.ValueOf(getCert).Pointer())
	require.EqualValues(t, tls.VersionTLS12, innerConf.MaxVersion)
}
