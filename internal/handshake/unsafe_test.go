package handshake

import (
	"crypto/tls"
	"net"
	"unsafe"

	"github.com/marten-seemann/qtls"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

type target struct {
	Name    string
	Version string

	callback func(label string, length int) error
}

type renamedField struct {
	NewName string
	Version string

	callback func(label string, length int) error
}

type renamedPrivateField struct {
	Name    string
	Version string

	cb func(label string, length int) error
}

type additionalField struct {
	Name    string
	Version string

	callback func(label string, length int) error
	secret   []byte
}

type interchangedFields struct {
	Version string
	Name    string

	callback func(label string, length int) error
}

type renamedCallbackFunctionParams struct { // should be equivalent
	Name    string
	Version string

	callback func(newLabel string, length int) error
}

var _ = Describe("Unsafe checks", func() {
	It("detects if an unsafe conversion is safe", func() {
		Expect(structsEqual(&target{}, &target{})).To(BeTrue())
		Expect(structsEqual(&target{}, &renamedField{})).To(BeFalse())
		Expect(structsEqual(&target{}, &renamedPrivateField{})).To(BeFalse())
		Expect(structsEqual(&target{}, &additionalField{})).To(BeFalse())
		Expect(structsEqual(&target{}, &interchangedFields{})).To(BeFalse())
		Expect(structsEqual(&target{}, &renamedCallbackFunctionParams{})).To(BeTrue())
	})

	It("converts a qtls.ClientHelloInfo to a tls.ClientHelloInfo", func() {
		chi := &qtlsClientHelloInfo{
			CipherSuites:      []uint16{1, 2, 3},
			ServerName:        "foo.bar",
			SupportedCurves:   []qtls.CurveID{4, 5, 6},
			SupportedPoints:   []uint8{7, 8, 9},
			SignatureSchemes:  []qtls.SignatureScheme{10, 11, 12},
			SupportedProtos:   []string{"foo", "bar"},
			SupportedVersions: []uint16{13, 14, 15},
			Conn:              &net.UDPConn{},
			config: &qtls.Config{
				MinVersion:       tls.VersionTLS10,
				MaxVersion:       tls.VersionTLS12,
				CipherSuites:     []uint16{16, 17, 18},
				CurvePreferences: []qtls.CurveID{19, 20, 21},
			},
		}
		tlsCHI := toTLSClientHelloInfo((*qtls.ClientHelloInfo)(unsafe.Pointer(chi)))
		Expect(tlsCHI.CipherSuites).To(Equal([]uint16{1, 2, 3}))
		Expect(tlsCHI.ServerName).To(Equal("foo.bar"))
		Expect(tlsCHI.SupportedCurves).To(Equal([]tls.CurveID{4, 5, 6}))
		Expect(tlsCHI.SupportedPoints).To(Equal([]uint8{7, 8, 9}))
		Expect(tlsCHI.SignatureSchemes).To(Equal([]tls.SignatureScheme{10, 11, 12}))
		Expect(tlsCHI.SupportedProtos).To(Equal([]string{"foo", "bar"}))
		Expect(tlsCHI.SupportedVersions).To(Equal([]uint16{13, 14, 15}))
		Expect(tlsCHI.Conn).To(Equal(&net.UDPConn{}))
		c := (*clientHelloInfo)(unsafe.Pointer(tlsCHI))
		Expect(c.config.CipherSuites).To(Equal([]uint16{16, 17, 18}))
		Expect(c.config.MinVersion).To(BeEquivalentTo(tls.VersionTLS10))
		Expect(c.config.MaxVersion).To(BeEquivalentTo(tls.VersionTLS12))
		Expect(c.config.CurvePreferences).To(Equal([]tls.CurveID{19, 20, 21}))
	})
})
