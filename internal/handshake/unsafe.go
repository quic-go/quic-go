package handshake

// This package uses unsafe to convert between:
// * qtls.Certificate and tls.Certificate
// * qtls.CertificateRequestInfo and tls.CertificateRequestInfo
// * qtls.ClientHelloInfo and tls.ClientHelloInfo
// * qtls.ConnectionState and tls.ConnectionState
// * qtls.ClientSessionState and tls.ClientSessionState
// We check in init() that this conversion actually is safe.

import (
	"crypto/tls"
	"net"
	"reflect"
	"unsafe"

	"github.com/marten-seemann/qtls"
)

func init() {
	if !structsEqual(&tls.Certificate{}, &qtls.Certificate{}) {
		panic("qtls.Certificate not compatible with tls.Certificate")
	}
	if !structsEqual(&tls.CertificateRequestInfo{}, &qtls.CertificateRequestInfo{}) {
		panic("qtls.CertificateRequestInfo not compatible with tls.CertificateRequestInfo")
	}
	if !structsEqual(&tls.ClientSessionState{}, &qtls.ClientSessionState{}) {
		panic("qtls.ClientSessionState not compatible with tls.ClientSessionState")
	}
	if !structsEqual(&tls.ClientSessionState{}, &clientSessionState{}) {
		panic("clientSessionState not compatible with tls.ClientSessionState")
	}
	if !structsEqual(&tls.ClientHelloInfo{}, &clientHelloInfo{}) {
		panic("clientHelloInfo not compatible with tls.ClientHelloInfo")
	}
	if !structsEqual(&qtls.ClientHelloInfo{}, &qtlsClientHelloInfo{}) {
		panic("qtlsClientHelloInfo not compatible with qtls.ClientHelloInfo")
	}
}

func structsEqual(a, b interface{}) bool {
	sa := reflect.ValueOf(a).Elem()
	sb := reflect.ValueOf(b).Elem()
	if sa.NumField() != sb.NumField() {
		return false
	}
	for i := 0; i < sa.NumField(); i++ {
		fa := sa.Type().Field(i)
		fb := sb.Type().Field(i)
		if !reflect.DeepEqual(fa.Index, fb.Index) || fa.Name != fb.Name || fa.Anonymous != fb.Anonymous || fa.Offset != fb.Offset || !reflect.DeepEqual(fa.Type, fb.Type) {
			return false
		}
	}
	return true
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
