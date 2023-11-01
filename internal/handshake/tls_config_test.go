package handshake

import (
	"crypto/tls"
	"net"
	"reflect"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestMinimumTLSVersion(t *testing.T) {
	local := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 42}
	remote := &net.UDPAddr{IP: net.IPv4(192, 168, 0, 1), Port: 1337}

	orig := &tls.Config{MinVersion: tls.VersionTLS12}
	conf := setupConfigForServer(orig, local, remote)
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
	conf := setupConfigForServer(tlsConf, local, remote)
	_, err := conf.GetCertificate(&tls.ClientHelloInfo{})
	require.NoError(t, err)
	require.Equal(t, local, localAddr)
	require.Equal(t, remote, remoteAddr)
}

func TestServerConfigGetConfigForClient(t *testing.T) {
	local := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 42}
	remote := &net.UDPAddr{IP: net.IPv4(192, 168, 0, 1), Port: 1337}

	var localAddr, remoteAddr net.Addr
	tlsConf := setupConfigForServer(
		&tls.Config{
			GetConfigForClient: func(info *tls.ClientHelloInfo) (*tls.Config, error) {
				localAddr = info.Conn.LocalAddr()
				remoteAddr = info.Conn.RemoteAddr()
				return &tls.Config{}, nil
			},
		},
		local,
		remote,
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
	tlsConf = setupConfigForServer(tlsConf, local, remote)
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
