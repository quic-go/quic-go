// +build go1.14

package handshake

import (
	"crypto/tls"
	"net"
	"unsafe"

	"github.com/marten-seemann/qtls"
)

func init() {
	if !structsEqual(&tls.ClientHelloInfo{}, &clientHelloInfo{}) {
		panic("clientHelloInfo not compatible with tls.ClientHelloInfo")
	}
	if !structsEqual(&qtls.ClientHelloInfo{}, &qtlsClientHelloInfo{}) {
		panic("qtlsClientHelloInfo not compatible with qtls.ClientHelloInfo")
	}
}

func cipherSuiteName(id uint16) string { return qtls.CipherSuiteName(id) }

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

	config *qtls.Config
}

func toTLSClientHelloInfo(chi *qtls.ClientHelloInfo) *tls.ClientHelloInfo {
	if chi == nil {
		return nil
	}
	qtlsCHI := (*qtlsClientHelloInfo)(unsafe.Pointer(chi))
	var config *tls.Config
	if qtlsCHI.config != nil {
		config = qtlsConfigToTLSConfig((*qtls.Config)(unsafe.Pointer(qtlsCHI.config)))
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

// qtlsConfigToTLSConfig is used to transform a qtls.Config to a tls.Config.
// It is used to create the tls.Config in the ClientHelloInfo.
// It doesn't copy all values, but only those used by ClientHelloInfo.SupportsCertificate.
func qtlsConfigToTLSConfig(config *qtls.Config) *tls.Config {
	return &tls.Config{
		MinVersion:       config.MinVersion,
		MaxVersion:       config.MaxVersion,
		CipherSuites:     config.CipherSuites,
		CurvePreferences: config.CurvePreferences,
	}
}
