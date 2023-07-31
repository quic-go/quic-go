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
			&tls.QUICTransportParametersExtension{
				TransportParameters: tls.TransportParameters{
					tls.InitialMaxStreamDataBidiRemote(0x100000),
					tls.InitialMaxStreamsBidi(16),
					tls.MaxDatagramFrameSize(1200),
					tls.MaxIdleTimeout(30000),
					tls.ActiveConnectionIDLimit(8),
					&tls.GREASEQUICBit{},
					&tls.VersionInformation{
						ChoosenVersion: tls.VERSION_1,
						AvailableVersions: []uint32{
							tls.VERSION_GREASE,
							tls.VERSION_1,
						},
						LegacyID: true,
					},
					tls.InitialMaxStreamsUni(16),
					&tls.GREASE{
						IdOverride: 0xff02de1a,
						ValueOverride: []byte{
							0x43, 0xe8,
						},
					},
					tls.InitialMaxStreamDataBidiLocal(0xc00000),
					tls.InitialMaxStreamDataUni(0x100000),
					tls.InitialSourceConnectionID([]byte{}),
					tls.MaxAckDelay(20),
					tls.InitialMaxData(0x1800000),
					&tls.DisableActiveMigration{},
				},
			},
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
