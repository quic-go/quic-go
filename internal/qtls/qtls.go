// +build !go1.15

package qtls

// This package uses unsafe to convert between:
// * Certificate and tls.Certificate
// * CertificateRequestInfo and tls.CertificateRequestInfo
// * ClientHelloInfo and tls.ClientHelloInfo
// * ConnectionState and tls.ConnectionState
// * ClientSessionState and tls.ClientSessionState
// We check in init() that this conversion actually is safe.

import (
	"crypto/tls"
	"net"
	"unsafe"
)

func init() {
	if !structsEqual(&tls.Certificate{}, &Certificate{}) {
		panic("Certificate not compatible with tls.Certificate")
	}
	if !structsEqual(&tls.CertificateRequestInfo{}, &CertificateRequestInfo{}) {
		panic("CertificateRequestInfo not compatible with tls.CertificateRequestInfo")
	}
	if !structsEqual(&tls.ClientSessionState{}, &ClientSessionState{}) {
		panic("ClientSessionState not compatible with tls.ClientSessionState")
	}
	if !structsEqual(&tls.ClientHelloInfo{}, &clientHelloInfo{}) {
		panic("clientHelloInfo not compatible with tls.ClientHelloInfo")
	}
	if !structsEqual(&ClientHelloInfo{}, &qtlsClientHelloInfo{}) {
		panic("qtlsClientHelloInfo not compatible with ClientHelloInfo")
	}
}

func tlsConfigToQtlsConfig(c *tls.Config, ec *ExtraConfig) *Config {
	if c == nil {
		c = &tls.Config{}
	}
	if ec == nil {
		ec = &ExtraConfig{}
	}
	// Clone the config first. This executes the tls.Config.serverInit().
	// This sets the SessionTicketKey, if the user didn't supply one.
	c = c.Clone()
	// QUIC requires TLS 1.3 or newer
	minVersion := c.MinVersion
	if minVersion < tls.VersionTLS13 {
		minVersion = tls.VersionTLS13
	}
	maxVersion := c.MaxVersion
	if maxVersion < tls.VersionTLS13 {
		maxVersion = tls.VersionTLS13
	}
	var getConfigForClient func(ch *ClientHelloInfo) (*Config, error)
	if c.GetConfigForClient != nil {
		getConfigForClient = func(ch *ClientHelloInfo) (*Config, error) {
			tlsConf, err := c.GetConfigForClient(toTLSClientHelloInfo(ch))
			if err != nil {
				return nil, err
			}
			if tlsConf == nil {
				return nil, nil
			}
			return tlsConfigToQtlsConfig(tlsConf, ec), nil
		}
	}
	var getCertificate func(ch *ClientHelloInfo) (*Certificate, error)
	if c.GetCertificate != nil {
		getCertificate = func(ch *ClientHelloInfo) (*Certificate, error) {
			cert, err := c.GetCertificate(toTLSClientHelloInfo(ch))
			if err != nil {
				return nil, err
			}
			if cert == nil {
				return nil, nil
			}
			return (*Certificate)(cert), nil
		}
	}
	var csc ClientSessionCache
	if c.ClientSessionCache != nil {
		csc = &clientSessionCache{c.ClientSessionCache}
	}
	conf := &Config{
		Rand:         c.Rand,
		Time:         c.Time,
		Certificates: *(*[]Certificate)(unsafe.Pointer(&c.Certificates)),
		//nolint:staticcheck // NameToCertificate is deprecated, but we still need to copy it if the user sets it.
		NameToCertificate:         *(*map[string]*Certificate)(unsafe.Pointer(&c.NameToCertificate)),
		GetCertificate:            getCertificate,
		GetClientCertificate:      *(*func(*CertificateRequestInfo) (*Certificate, error))(unsafe.Pointer(&c.GetClientCertificate)),
		GetConfigForClient:        getConfigForClient,
		VerifyPeerCertificate:     c.VerifyPeerCertificate,
		RootCAs:                   c.RootCAs,
		NextProtos:                c.NextProtos,
		EnforceNextProtoSelection: true,
		ServerName:                c.ServerName,
		ClientAuth:                c.ClientAuth,
		ClientCAs:                 c.ClientCAs,
		InsecureSkipVerify:        c.InsecureSkipVerify,
		CipherSuites:              c.CipherSuites,
		PreferServerCipherSuites:  c.PreferServerCipherSuites,
		SessionTicketsDisabled:    c.SessionTicketsDisabled,
		//nolint:staticcheck // SessionTicketKey is deprecated, but we still need to copy it if the user sets it.
		SessionTicketKey:            c.SessionTicketKey,
		ClientSessionCache:          csc,
		MinVersion:                  minVersion,
		MaxVersion:                  maxVersion,
		CurvePreferences:            c.CurvePreferences,
		DynamicRecordSizingDisabled: c.DynamicRecordSizingDisabled,
		// no need to copy Renegotiation, it's not supported by TLS 1.3
		KeyLogWriter:               c.KeyLogWriter,
		AlternativeRecordLayer:     ec.AlternativeRecordLayer,
		GetExtensions:              ec.GetExtensions,
		ReceivedExtensions:         ec.ReceivedExtensions,
		Accept0RTT:                 ec.Accept0RTT,
		Rejected0RTT:               ec.Rejected0RTT,
		GetAppDataForSessionState:  ec.GetAppDataForSessionState,
		SetAppDataFromSessionState: ec.SetAppDataFromSessionState,
		Enable0RTT:                 ec.Enable0RTT,
		MaxEarlyData:               ec.MaxEarlyData,
	}
	return conf
}

type clientSessionCache struct {
	tls.ClientSessionCache
}

var _ ClientSessionCache = &clientSessionCache{}

func (c *clientSessionCache) Get(sessionKey string) (*ClientSessionState, bool) {
	sess, ok := c.ClientSessionCache.Get(sessionKey)
	if sess == nil {
		return nil, ok
	}
	// ClientSessionState is identical to the tls.ClientSessionState.
	// In order to allow users of quic-go to use a tls.Config,
	// we need this workaround to use the ClientSessionCache.
	// In unsafe.go we check that the two structs are actually identical.
	return (*ClientSessionState)(unsafe.Pointer(sess)), ok
}

func (c *clientSessionCache) Put(sessionKey string, cs *ClientSessionState) {
	if cs == nil {
		c.ClientSessionCache.Put(sessionKey, nil)
		return
	}
	// ClientSessionState is identical to the tls.ClientSessionState.
	// In order to allow users of quic-go to use a tls.Config,
	// we need this workaround to use the ClientSessionCache.
	// In unsafe.go we check that the two structs are actually identical.
	c.ClientSessionCache.Put(sessionKey, (*tls.ClientSessionState)(unsafe.Pointer(cs)))
}

type clientHelloInfo struct {
	CipherSuites      []uint16
	ServerName        string
	SupportedCurves   []tls.CurveID
	SupportedPoints   []uint8
	SignatureSchemes  []tls.SignatureScheme
	SupportedProtos   []string
	SupportedVersions []uint16
	Conn              net.Conn

	config *tls.Config
}

type qtlsClientHelloInfo struct {
	CipherSuites      []uint16
	ServerName        string
	SupportedCurves   []tls.CurveID
	SupportedPoints   []uint8
	SignatureSchemes  []tls.SignatureScheme
	SupportedProtos   []string
	SupportedVersions []uint16
	Conn              net.Conn

	config *Config
}

func toTLSClientHelloInfo(chi *ClientHelloInfo) *tls.ClientHelloInfo {
	if chi == nil {
		return nil
	}
	qtlsCHI := (*qtlsClientHelloInfo)(unsafe.Pointer(chi))
	var config *tls.Config
	if qtlsCHI.config != nil {
		config = qtlsConfigToTLSConfig(qtlsCHI.config)
	}
	return (*tls.ClientHelloInfo)(unsafe.Pointer(&clientHelloInfo{
		CipherSuites:      chi.CipherSuites,
		ServerName:        chi.ServerName,
		SupportedCurves:   chi.SupportedCurves,
		SupportedPoints:   chi.SupportedPoints,
		SignatureSchemes:  chi.SignatureSchemes,
		SupportedProtos:   chi.SupportedProtos,
		SupportedVersions: chi.SupportedVersions,
		Conn:              chi.Conn,
		config:            config,
	}))
}

// qtlsConfigToTLSConfig is used to transform a Config to a tls.Config.
// It is used to create the tls.Config in the ClientHelloInfo.
// It doesn't copy all values, but only those used by ClientHelloInfo.SupportsCertificate.
func qtlsConfigToTLSConfig(config *Config) *tls.Config {
	return &tls.Config{
		MinVersion:       config.MinVersion,
		MaxVersion:       config.MaxVersion,
		CipherSuites:     config.CipherSuites,
		CurvePreferences: config.CurvePreferences,
	}
}
