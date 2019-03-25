package handshake

import (
	"crypto/tls"

	"github.com/marten-seemann/qtls"
)

func tlsConfigToQtlsConfig(
	c *tls.Config,
	recordLayer qtls.RecordLayer,
	extHandler tlsExtensionHandler,
) *qtls.Config {
	if c == nil {
		c = &tls.Config{}
	}
	// QUIC requires TLS 1.3 or newer
	minVersion := c.MinVersion
	if minVersion < qtls.VersionTLS13 {
		minVersion = qtls.VersionTLS13
	}
	maxVersion := c.MaxVersion
	if maxVersion < qtls.VersionTLS13 {
		maxVersion = qtls.VersionTLS13
	}
	var getConfigForClient func(ch *tls.ClientHelloInfo) (*qtls.Config, error)
	if c.GetConfigForClient != nil {
		getConfigForClient = func(ch *tls.ClientHelloInfo) (*qtls.Config, error) {
			tlsConf, err := c.GetConfigForClient(ch)
			if err != nil {
				return nil, err
			}
			if tlsConf == nil {
				return nil, nil
			}
			return tlsConfigToQtlsConfig(tlsConf, recordLayer, extHandler), nil
		}
	}
	return &qtls.Config{
		Rand:                        c.Rand,
		Time:                        c.Time,
		Certificates:                c.Certificates,
		NameToCertificate:           c.NameToCertificate,
		GetCertificate:              c.GetCertificate,
		GetClientCertificate:        c.GetClientCertificate,
		GetConfigForClient:          getConfigForClient,
		VerifyPeerCertificate:       c.VerifyPeerCertificate,
		RootCAs:                     c.RootCAs,
		NextProtos:                  c.NextProtos,
		ServerName:                  c.ServerName,
		ClientAuth:                  c.ClientAuth,
		ClientCAs:                   c.ClientCAs,
		InsecureSkipVerify:          c.InsecureSkipVerify,
		CipherSuites:                c.CipherSuites,
		PreferServerCipherSuites:    c.PreferServerCipherSuites,
		SessionTicketsDisabled:      c.SessionTicketsDisabled,
		SessionTicketKey:            c.SessionTicketKey,
		MinVersion:                  minVersion,
		MaxVersion:                  maxVersion,
		CurvePreferences:            c.CurvePreferences,
		DynamicRecordSizingDisabled: c.DynamicRecordSizingDisabled,
		// no need to copy Renegotiation, it's not supported by TLS 1.3
		KeyLogWriter:           c.KeyLogWriter,
		AlternativeRecordLayer: recordLayer,
		GetExtensions:          extHandler.GetExtensions,
		ReceivedExtensions:     extHandler.ReceivedExtensions,
	}
}
