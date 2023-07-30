package main

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"

	tls "github.com/refraction-networking/utls"

	quic "github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"

	qtp "github.com/quic-go/quic-go/transportparameters"
)

func getCHS() *tls.ClientHelloSpec {
	return &tls.ClientHelloSpec{
		TLSVersMin: tls.VersionTLS13,
		TLSVersMax: tls.VersionTLS13,
		CipherSuites: []uint16{
			tls.TLS_AES_128_GCM_SHA256,
			tls.TLS_CHACHA20_POLY1305_SHA256,
			tls.TLS_AES_256_GCM_SHA384,
		},
		CompressionMethods: []uint8{
			0x0, // no compression
		},
		Extensions: []tls.TLSExtension{
			&tls.SNIExtension{},
			&tls.ExtendedMasterSecretExtension{},
			&tls.RenegotiationInfoExtension{
				Renegotiation: tls.RenegotiateOnceAsClient,
			},
			&tls.SupportedCurvesExtension{
				Curves: []tls.CurveID{
					tls.CurveX25519,
					tls.CurveSECP256R1,
					tls.CurveSECP384R1,
					tls.CurveSECP521R1,
					tls.FakeCurveFFDHE2048,
					tls.FakeCurveFFDHE3072,
					tls.FakeCurveFFDHE4096,
					tls.FakeCurveFFDHE6144,
					tls.FakeCurveFFDHE8192,
				},
			},
			&tls.ALPNExtension{
				AlpnProtocols: []string{
					"h3",
				},
			},
			&tls.StatusRequestExtension{},
			&tls.FakeDelegatedCredentialsExtension{
				SupportedSignatureAlgorithms: []tls.SignatureScheme{
					tls.ECDSAWithP256AndSHA256,
					tls.ECDSAWithP384AndSHA384,
					tls.ECDSAWithP521AndSHA512,
					tls.ECDSAWithSHA1,
				},
			},
			&tls.KeyShareExtension{
				KeyShares: []tls.KeyShare{
					{
						Group: tls.X25519,
					},
					// {
					// 	Group: tls.CurveP256,
					// },
				},
			},
			&tls.SupportedVersionsExtension{
				Versions: []uint16{
					tls.VersionTLS13,
				},
			},
			&tls.SignatureAlgorithmsExtension{
				SupportedSignatureAlgorithms: []tls.SignatureScheme{
					tls.ECDSAWithP256AndSHA256,
					tls.ECDSAWithP384AndSHA384,
					tls.ECDSAWithP521AndSHA512,
					tls.ECDSAWithSHA1,
					tls.PSSWithSHA256,
					tls.PSSWithSHA384,
					tls.PSSWithSHA512,
					tls.PKCS1WithSHA256,
					tls.PKCS1WithSHA384,
					tls.PKCS1WithSHA512,
					tls.PKCS1WithSHA1,
				},
			},
			&tls.PSKKeyExchangeModesExtension{
				Modes: []uint8{
					tls.PskModeDHE,
				},
			},
			&tls.FakeRecordSizeLimitExtension{
				Limit: 0x4001,
			},
			&tls.QUICTransportParametersExtension{},
			&tls.UtlsPaddingExtension{
				GetPaddingLen: tls.BoringPaddingStyle,
			},
		},
	}
}

func main() {
	keyLogWriter, err := os.Create("./keylog.txt")
	if err != nil {
		panic(err)
	}

	tlsConf := &tls.Config{
		ServerName: "quic.tlsfingerprint.io",
		// ServerName: "www.cloudflare.com",
		// MinVersion:   tls.VersionTLS13,
		KeyLogWriter: keyLogWriter,
		// NextProtos:   []string{"h3"},
	}

	quicConf := &quic.Config{
		Versions: []quic.VersionNumber{quic.Version1},
		// EnableDatagrams:        true,
		SrcConnIDLength:        3, // <4 causes timeout
		DestConnIDLength:       8,
		InitPacketNumber:       0,
		InitPacketNumberLength: quic.PacketNumberLen1, // currently only affects the initial packet number
		// Versions: []quic.VersionNumber{quic.Version2},
		TransportParameters: qtp.TransportParameters{
			qtp.InitialMaxStreamDataBidiRemote(0x100000),
			qtp.InitialMaxStreamsBidi(16),
			qtp.MaxDatagramFrameSize(1200),
			qtp.MaxIdleTimeout(30000),
			qtp.ActiveConnectionIDLimit(8),
			&qtp.GREASEQUICBit{},
			&qtp.VersionInformation{
				ChoosenVersion: qtp.VERSION_1,
				AvailableVersions: []uint32{
					qtp.VERSION_GREASE,
					qtp.VERSION_1,
				},
				LegacyID: true,
			},
			qtp.InitialMaxStreamsUni(16),
			&qtp.GREASE{
				IdOverride: 0xff02de1a,
				ValueOverride: []byte{
					0x43, 0xe8,
				},
			},
			qtp.InitialMaxStreamDataBidiLocal(0xc00000),
			qtp.InitialMaxStreamDataUni(0x100000),
			qtp.InitialSourceConnectionID([]byte{}),
			qtp.MaxAckDelay(20),
			qtp.InitialMaxData(0x1800000),
			&qtp.DisableActiveMigration{},
		},
	}

	roundTripper := &http3.RoundTripper{
		TLSClientConfig: tlsConf,
		QuicConfig:      quicConf,
		ClientHelloSpec: getCHS(),
	}
	defer roundTripper.Close()

	hclient := &http.Client{
		Transport: roundTripper,
	}

	addr := "https://quic.tlsfingerprint.io/qfp/"
	// addr := "https://www.cloudflare.com"

	rsp, err := hclient.Get(addr)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Got response for %s: %#v", addr, rsp)

	body := &bytes.Buffer{}
	_, err = io.Copy(body, rsp.Body)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Response Body: %s", body.Bytes())
}
