package quic

import (
	"crypto/rand"
	"fmt"
	"math/big"
	mrand "math/rand"

	tls "github.com/Noooste/utls"
)

type QUICID struct {
	Client string

	// Version specifies version of a mimicked clients (e.g. browsers).
	Version string

	// Fingerprint is a unique identifier for each different QUIC client/spec.
	Fingerprint string
}

const (
	// clients
	quicFirefox = "Firefox"
	quicChrome  = "Chrome"
	quicIOS     = "iOS"
	quicAndroid = "Android"
	quicEdge    = "Edge"
	quicSafari  = "Safari"
)

var (
	QUICFirefox_116  = QUICFirefox_116A                               // point to most-popular 8-byte DCID
	QUICFirefox_116A = QUICID{quicFirefox, "116", "31ea0e4ffd75b477"} // DCID.len = 8
	QUICFirefox_116B = QUICID{quicFirefox, "116", "d07d3c9152fbc5e0"} // DCID.len = 9
	QUICFirefox_116C = QUICID{quicFirefox, "116", "c74f87b2a9ccc006"} // DCID.len = 15
	// TODO: add Firefox fingerprints with Token and PSK extension

	QUICChrome_115      = QUICChrome_115_IPv4                               // IPv4 is still more popular
	QUICChrome_115_IPv4 = QUICID{quicChrome, "115", "beeb454235791d5c"}     // IPv4: UDP payload 20-byte longer than IPv6 due to padding
	QUICChrome_115_IPv6 = QUICID{quicChrome, "115_ip6", "beeb454235791d5c"} // IPv6
	// TODO: add Chrome fingerprints with Token and PSK extension

	// TODO: add more QUIC clients and versions
)

func QUICID2Spec(id QUICID) (QUICSpec, error) {
	switch id {
	case QUICChrome_115_IPv4:
		return QUICSpec{
			InitialPacketSpec: InitialPacketSpec{
				SrcConnIDLength:        0,
				DestConnIDLength:       8,
				InitPacketNumberLength: 1,
				InitPacketNumber:       1, // Chrome is special that it starts with 1 not 0
				ClientTokenLength:      0,
				FrameBuilder: &QUICRandomFrames{ // Chrome randomly inserts padding frames
					MinPING:    0,
					MaxPING:    10,
					MinCRYPTO:  1,
					MaxCRYPTO:  10,
					MinPADDING: 3,
					MaxPADDING: 6,
					Length:     1231 - 16, // 16-byte for Auth Tag
				},
			},
			ClientHelloSpec: &tls.ClientHelloSpec{
				TLSVersMin: tls.VersionTLS13,
				TLSVersMax: tls.VersionTLS13,
				CipherSuites: []uint16{
					tls.TLS_AES_128_GCM_SHA256,
					tls.TLS_AES_256_GCM_SHA384,
					tls.TLS_CHACHA20_POLY1305_SHA256,
				},
				CompressionMethods: []uint8{
					0x0, // no compression
				},
				Extensions: tls.ShuffleChromeTLSExtensions([]tls.TLSExtension{
					ShuffleQUICTransportParameters(&tls.QUICTransportParametersExtension{ // Order of QTPs are always shuffled
						TransportParameters: tls.TransportParameters{
							tls.InitialMaxStreamsUni(103),
							tls.MaxIdleTimeout(30000),
							tls.InitialMaxData(15728640),
							tls.InitialMaxStreamDataUni(6291456),
							&tls.VersionInformation{
								ChoosenVersion: tls.VERSION_1,
								AvailableVersions: []uint32{
									tls.VERSION_GREASE,
									tls.VERSION_1,
								},
								LegacyID: true,
							},
							&tls.FakeQUICTransportParameter{ // google_quic_version
								Id:  0x4752,
								Val: []byte{00, 00, 00, 01}, // Google QUIC version 1
							},
							&tls.FakeQUICTransportParameter{ // google_connection_options
								Id:  0x3128,
								Val: []byte{0x52, 0x56, 0x43, 0x4d},
							},
							tls.MaxDatagramFrameSize(65536),
							tls.InitialMaxStreamsBidi(100),
							tls.InitialMaxStreamDataBidiLocal(6291456),
							VariableLengthGREASEQTP(0x10), // Random length for GREASE QTP
							tls.InitialSourceConnectionID([]byte{}),
							tls.MaxUDPPayloadSize(1472),
							tls.InitialMaxStreamDataBidiRemote(6291456),
						},
					}),
					&tls.ApplicationSettingsExtension{
						SupportedProtocols: []string{
							"h3",
						},
					},
					&tls.UtlsCompressCertExtension{
						Algorithms: []tls.CertCompressionAlgo{
							tls.CertCompressionBrotli,
						},
					},
					&tls.KeyShareExtension{
						KeyShares: []tls.KeyShare{
							{
								Group: tls.X25519,
							},
						},
					},
					&tls.SignatureAlgorithmsExtension{
						SupportedSignatureAlgorithms: []tls.SignatureScheme{
							tls.ECDSAWithP256AndSHA256,
							tls.PSSWithSHA256,
							tls.PKCS1WithSHA256,
							tls.ECDSAWithP384AndSHA384,
							tls.PSSWithSHA384,
							tls.PKCS1WithSHA384,
							tls.PSSWithSHA512,
							tls.PKCS1WithSHA512,
							tls.PKCS1WithSHA1,
						},
					},
					&tls.SNIExtension{},
					&tls.SupportedCurvesExtension{
						Curves: []tls.CurveID{
							tls.CurveX25519,
							tls.CurveSECP256R1,
							tls.CurveSECP384R1,
						},
					},
					&tls.PSKKeyExchangeModesExtension{
						Modes: []uint8{
							tls.PskModeDHE,
						},
					},
					&tls.ALPNExtension{
						AlpnProtocols: []string{
							"h3",
						},
					},
					&tls.SupportedVersionsExtension{
						Versions: []uint16{
							tls.VersionTLS13,
						},
					},
				}),
			},
		}, nil
	case QUICChrome_115_IPv6:
		return QUICSpec{
			InitialPacketSpec: InitialPacketSpec{
				SrcConnIDLength:        0,
				DestConnIDLength:       8,
				InitPacketNumberLength: 1,
				InitPacketNumber:       1, // Chrome is special that it starts with 1 not 0
				ClientTokenLength:      0,
				FrameBuilder: &QUICRandomFrames{ // Chrome randomly inserts padding frames
					MinPING:    0,
					MaxPING:    10,
					MinCRYPTO:  1,
					MaxCRYPTO:  10,
					MinPADDING: 3,
					MaxPADDING: 6,
					Length:     1211 - 16, // IPv6 pads to a length that is 20-byte shorter than IPv4's version
				},
			},
			ClientHelloSpec: &tls.ClientHelloSpec{
				TLSVersMin: tls.VersionTLS13,
				TLSVersMax: tls.VersionTLS13,
				CipherSuites: []uint16{
					tls.TLS_AES_128_GCM_SHA256,
					tls.TLS_AES_256_GCM_SHA384,
					tls.TLS_CHACHA20_POLY1305_SHA256,
				},
				CompressionMethods: []uint8{
					0x0,
				},
				Extensions: tls.ShuffleChromeTLSExtensions([]tls.TLSExtension{
					ShuffleQUICTransportParameters(&tls.QUICTransportParametersExtension{ // Order of QTPs are always shuffled
						TransportParameters: tls.TransportParameters{
							tls.InitialMaxStreamsUni(103),
							tls.MaxIdleTimeout(30000),
							tls.InitialMaxData(15728640),
							tls.InitialMaxStreamDataUni(6291456),
							&tls.VersionInformation{
								ChoosenVersion: tls.VERSION_1,
								AvailableVersions: []uint32{
									tls.VERSION_GREASE,
									tls.VERSION_1,
								},
								LegacyID: true,
							},
							&tls.FakeQUICTransportParameter{ // google_quic_version
								Id:  0x4752,
								Val: []byte{00, 00, 00, 01}, // Google QUIC version 1
							},
							&tls.FakeQUICTransportParameter{ // google_connection_options
								Id:  0x3128,
								Val: []byte{0x52, 0x56, 0x43, 0x4d},
							},
							tls.MaxDatagramFrameSize(65536),
							tls.InitialMaxStreamsBidi(100),
							tls.InitialMaxStreamDataBidiLocal(6291456),
							VariableLengthGREASEQTP(0x10), // Random length for GREASE QTP
							tls.InitialSourceConnectionID([]byte{}),
							tls.MaxUDPPayloadSize(1472),
							tls.InitialMaxStreamDataBidiRemote(6291456),
						},
					}),
					&tls.ApplicationSettingsExtension{
						SupportedProtocols: []string{
							"h3",
						},
					},
					&tls.UtlsCompressCertExtension{
						Algorithms: []tls.CertCompressionAlgo{
							tls.CertCompressionBrotli,
						},
					},
					&tls.KeyShareExtension{
						KeyShares: []tls.KeyShare{
							{
								Group: tls.X25519,
							},
						},
					},
					&tls.SignatureAlgorithmsExtension{
						SupportedSignatureAlgorithms: []tls.SignatureScheme{
							tls.ECDSAWithP256AndSHA256,
							tls.PSSWithSHA256,
							tls.PKCS1WithSHA256,
							tls.ECDSAWithP384AndSHA384,
							tls.PSSWithSHA384,
							tls.PKCS1WithSHA384,
							tls.PSSWithSHA512,
							tls.PKCS1WithSHA512,
							tls.PKCS1WithSHA1,
						},
					},
					&tls.SNIExtension{},
					&tls.SupportedCurvesExtension{
						Curves: []tls.CurveID{
							tls.CurveX25519,
							tls.CurveSECP256R1,
							tls.CurveSECP384R1,
						},
					},
					&tls.PSKKeyExchangeModesExtension{
						Modes: []uint8{
							tls.PskModeDHE,
						},
					},
					&tls.ALPNExtension{
						AlpnProtocols: []string{
							"h3",
						},
					},
					&tls.SupportedVersionsExtension{
						Versions: []uint16{
							tls.VersionTLS13,
						},
					},
				}),
			},
		}, nil
	case QUICFirefox_116A:
		return QUICSpec{
			InitialPacketSpec: InitialPacketSpec{
				SrcConnIDLength:        3,
				DestConnIDLength:       8,
				InitPacketNumberLength: 1,
				InitPacketNumber:       0,
				ClientTokenLength:      0,
				FrameBuilder:           QUICFrames{}, // empty = single crypto
			},
			ClientHelloSpec: &tls.ClientHelloSpec{
				TLSVersMin: tls.VersionTLS13,
				TLSVersMax: tls.VersionTLS13,
				CipherSuites: []uint16{
					tls.TLS_AES_128_GCM_SHA256,
					tls.TLS_CHACHA20_POLY1305_SHA256,
					tls.TLS_AES_256_GCM_SHA384,
				},
				CompressionMethods: []uint8{
					0x0,
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
					ShuffleQUICTransportParameters(&tls.QUICTransportParametersExtension{
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
							&tls.GREASETransportParameter{
								Length: 2, // Firefox uses 2-byte GREASE values
							},
							tls.InitialMaxStreamDataBidiLocal(0xc00000),
							tls.InitialMaxStreamDataUni(0x100000),
							tls.InitialSourceConnectionID([]byte{}),
							tls.MaxAckDelay(20),
							tls.InitialMaxData(0x1800000),
							&tls.DisableActiveMigration{},
						},
					}),
					&tls.UtlsPaddingExtension{
						GetPaddingLen: tls.BoringPaddingStyle,
					},
				},
			},
			UDPDatagramMinSize: 1357, // Firefox pads with zeroes at the end of UDP datagrams
		}, nil
	case QUICFirefox_116B:
		return QUICSpec{
			InitialPacketSpec: InitialPacketSpec{
				SrcConnIDLength:        3,
				DestConnIDLength:       9,
				InitPacketNumberLength: 1,
				InitPacketNumber:       0,
				ClientTokenLength:      0,
				FrameBuilder:           QUICFrames{},
			},
			ClientHelloSpec: &tls.ClientHelloSpec{
				TLSVersMin: tls.VersionTLS13,
				TLSVersMax: tls.VersionTLS13,
				CipherSuites: []uint16{
					tls.TLS_AES_128_GCM_SHA256,
					tls.TLS_CHACHA20_POLY1305_SHA256,
					tls.TLS_AES_256_GCM_SHA384,
				},
				CompressionMethods: []uint8{
					0x0,
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
					ShuffleQUICTransportParameters(&tls.QUICTransportParametersExtension{
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
							&tls.GREASETransportParameter{
								Length: 2, // Firefox uses 2-byte GREASE values
							},
							tls.InitialMaxStreamDataBidiLocal(0xc00000),
							tls.InitialMaxStreamDataUni(0x100000),
							tls.InitialSourceConnectionID([]byte{}),
							tls.MaxAckDelay(20),
							tls.InitialMaxData(0x1800000),
							&tls.DisableActiveMigration{},
						},
					}),
					&tls.UtlsPaddingExtension{
						GetPaddingLen: tls.BoringPaddingStyle,
					},
				},
			},
			UDPDatagramMinSize: 1357,
		}, nil
	case QUICFirefox_116C:
		return QUICSpec{
			InitialPacketSpec: InitialPacketSpec{
				SrcConnIDLength:        3,
				DestConnIDLength:       15,
				InitPacketNumberLength: 1,
				InitPacketNumber:       0,
				ClientTokenLength:      0,
				FrameBuilder:           QUICFrames{},
			},
			ClientHelloSpec: &tls.ClientHelloSpec{
				TLSVersMin: tls.VersionTLS13,
				TLSVersMax: tls.VersionTLS13,
				CipherSuites: []uint16{
					tls.TLS_AES_128_GCM_SHA256,
					tls.TLS_CHACHA20_POLY1305_SHA256,
					tls.TLS_AES_256_GCM_SHA384,
				},
				CompressionMethods: []uint8{
					0x0,
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
					ShuffleQUICTransportParameters(&tls.QUICTransportParametersExtension{
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
							&tls.GREASETransportParameter{
								Length: 2,
							},
							tls.InitialMaxStreamDataBidiLocal(0xc00000),
							tls.InitialMaxStreamDataUni(0x100000),
							tls.InitialSourceConnectionID([]byte{}),
							tls.MaxAckDelay(20),
							tls.InitialMaxData(0x1800000),
							&tls.DisableActiveMigration{},
						},
					}),
					&tls.UtlsPaddingExtension{
						GetPaddingLen: tls.BoringPaddingStyle,
					},
				},
			},
			UDPDatagramMinSize: 1357,
		}, nil
	default:
		return QUICSpec{}, fmt.Errorf("unknown QUIC ID: %v", id)
	}
}

func ShuffleTLSExtensions(exts []tls.TLSExtension) []tls.TLSExtension {
	mrand.Shuffle(len(exts), func(i, j int) {
		exts[i], exts[j] = exts[j], exts[i]
	})
	return exts
}

func ShuffleQUICTransportParameters(qtp *tls.QUICTransportParametersExtension) *tls.QUICTransportParametersExtension {
	// shuffle the order of parameters
	mrand.Shuffle(len(qtp.TransportParameters), func(i, j int) {
		qtp.TransportParameters[i], qtp.TransportParameters[j] = qtp.TransportParameters[j], qtp.TransportParameters[i]
	})
	return qtp
}

func VariableLengthGREASEQTP(maxLen int) *tls.GREASETransportParameter {
	// get random length for GREASE
	greaseMaxLen := big.NewInt(0x10)
	greaseLen, err := rand.Int(rand.Reader, greaseMaxLen)
	if err != nil {
		panic(err)
	}

	return &tls.GREASETransportParameter{
		Length: uint16(greaseLen.Uint64()),
	}
}
