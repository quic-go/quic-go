package handshake

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"time"

	mocktls "github.com/quic-go/quic-go/internal/mocks/tls"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/qerr"
	"github.com/quic-go/quic-go/internal/testdata"
	"github.com/quic-go/quic-go/internal/utils"
	"github.com/quic-go/quic-go/internal/wire"

	"github.com/golang/mock/gomock"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

const (
	typeClientHello      = 1
	typeNewSessionTicket = 4
)

var _ = Describe("Crypto Setup TLS", func() {
	var clientConf, serverConf *tls.Config

	BeforeEach(func() {
		serverConf = testdata.GetTLSConfig()
		serverConf.NextProtos = []string{"crypto-setup"}
		clientConf = &tls.Config{
			ServerName: "localhost",
			RootCAs:    testdata.GetRootCA(),
			NextProtos: []string{"crypto-setup"},
		}
	})

	It("handles qtls errors occurring before during ClientHello generation", func() {
		tlsConf := testdata.GetTLSConfig()
		tlsConf.InsecureSkipVerify = true
		tlsConf.NextProtos = []string{""}
		cl := NewCryptoSetupClient(
			protocol.ConnectionID{},
			&wire.TransportParameters{},
			tlsConf,
			false,
			&utils.RTTStats{},
			nil,
			utils.DefaultLogger.WithPrefix("client"),
			protocol.Version1,
		)

		Expect(cl.StartHandshake()).To(MatchError(&qerr.TransportError{
			ErrorCode:    qerr.InternalError,
			ErrorMessage: "tls: invalid NextProtos value",
		}))
	})

	It("errors when a message is received at the wrong encryption level", func() {
		var token protocol.StatelessResetToken
		server := NewCryptoSetupServer(
			protocol.ConnectionID{},
			&net.UDPAddr{IP: net.IPv6loopback, Port: 1234},
			&net.UDPAddr{IP: net.IPv6loopback, Port: 4321},
			&wire.TransportParameters{StatelessResetToken: &token},
			testdata.GetTLSConfig(),
			false,
			&utils.RTTStats{},
			nil,
			utils.DefaultLogger.WithPrefix("server"),
			protocol.Version1,
		)

		Expect(server.StartHandshake()).To(Succeed())

		fakeCH := append([]byte{typeClientHello, 0, 0, 6}, []byte("foobar")...)
		// wrong encryption level
		err := server.HandleMessage(fakeCH, protocol.EncryptionHandshake)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("tls: handshake data received at wrong level"))
	})

	Context("doing the handshake", func() {
		generateCert := func() tls.Certificate {
			priv, err := rsa.GenerateKey(rand.Reader, 2048)
			Expect(err).ToNot(HaveOccurred())
			tmpl := &x509.Certificate{
				SerialNumber:          big.NewInt(1),
				Subject:               pkix.Name{},
				SignatureAlgorithm:    x509.SHA256WithRSA,
				NotBefore:             time.Now(),
				NotAfter:              time.Now().Add(time.Hour), // valid for an hour
				BasicConstraintsValid: true,
			}
			certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, priv.Public(), priv)
			Expect(err).ToNot(HaveOccurred())
			return tls.Certificate{
				PrivateKey:  priv,
				Certificate: [][]byte{certDER},
			}
		}

		newRTTStatsWithRTT := func(rtt time.Duration) *utils.RTTStats {
			rttStats := &utils.RTTStats{}
			rttStats.UpdateRTT(rtt, 0, time.Now())
			ExpectWithOffset(1, rttStats.SmoothedRTT()).To(Equal(rtt))
			return rttStats
		}

		// The clientEvents and serverEvents contain all events that were not processed by the function,
		// i.e. not EventWriteInitialData, EventWriteHandshakeData, EventHandshakeComplete.
		handshake := func(client, server CryptoSetup) (clientEvents []Event, clientErr error, serverEvents []Event, serverErr error) {
			Expect(client.StartHandshake()).To(Succeed())
			Expect(server.StartHandshake()).To(Succeed())

			var clientHandshakeComplete, serverHandshakeComplete bool

			for {
			clientLoop:
				for {
					ev := client.NextEvent()
					//nolint:exhaustive // only need to process a few events
					switch ev.Kind {
					case EventNoEvent:
						break clientLoop
					case EventWriteInitialData:
						if err := server.HandleMessage(ev.Data, protocol.EncryptionInitial); err != nil {
							serverErr = err
							return
						}
					case EventWriteHandshakeData:
						if err := server.HandleMessage(ev.Data, protocol.EncryptionHandshake); err != nil {
							serverErr = err
							return
						}
					case EventHandshakeComplete:
						clientHandshakeComplete = true
					default:
						clientEvents = append(clientEvents, ev)
					}
				}

			serverLoop:
				for {
					ev := server.NextEvent()
					//nolint:exhaustive // only need to process a few events
					switch ev.Kind {
					case EventNoEvent:
						break serverLoop
					case EventWriteInitialData:
						if err := client.HandleMessage(ev.Data, protocol.EncryptionInitial); err != nil {
							clientErr = err
							return
						}
					case EventWriteHandshakeData:
						if err := client.HandleMessage(ev.Data, protocol.EncryptionHandshake); err != nil {
							clientErr = err
							return
						}
					case EventHandshakeComplete:
						serverHandshakeComplete = true
						ticket, err := server.GetSessionTicket()
						Expect(err).ToNot(HaveOccurred())
						if ticket != nil {
							Expect(client.HandleMessage(ticket, protocol.Encryption1RTT)).To(Succeed())
						}
					default:
						serverEvents = append(serverEvents, ev)
					}
				}

				if clientHandshakeComplete && serverHandshakeComplete {
					break
				}
			}
			return
		}

		handshakeWithTLSConf := func(
			clientConf, serverConf *tls.Config,
			clientRTTStats, serverRTTStats *utils.RTTStats,
			clientTransportParameters, serverTransportParameters *wire.TransportParameters,
			enable0RTT bool,
		) (CryptoSetup /* client */, []Event /* more client events */, error, /* client error */
			CryptoSetup /* server */, []Event /* more server events */, error, /* server error */
		) {
			client := NewCryptoSetupClient(
				protocol.ConnectionID{},
				clientTransportParameters,
				clientConf,
				enable0RTT,
				clientRTTStats,
				nil,
				utils.DefaultLogger.WithPrefix("client"),
				protocol.Version1,
			)

			if serverTransportParameters.StatelessResetToken == nil {
				var token protocol.StatelessResetToken
				serverTransportParameters.StatelessResetToken = &token
			}
			server := NewCryptoSetupServer(
				protocol.ConnectionID{},
				&net.UDPAddr{IP: net.IPv6loopback, Port: 1234},
				&net.UDPAddr{IP: net.IPv6loopback, Port: 4321},
				serverTransportParameters,
				serverConf,
				enable0RTT,
				serverRTTStats,
				nil,
				utils.DefaultLogger.WithPrefix("server"),
				protocol.Version1,
			)
			cEvents, cErr, sEvents, sErr := handshake(client, server)
			return client, cEvents, cErr, server, sEvents, sErr
		}

		It("handshakes", func() {
			_, _, clientErr, _, _, serverErr := handshakeWithTLSConf(
				clientConf, serverConf,
				&utils.RTTStats{}, &utils.RTTStats{},
				&wire.TransportParameters{ActiveConnectionIDLimit: 2}, &wire.TransportParameters{ActiveConnectionIDLimit: 2},
				false,
			)
			Expect(clientErr).ToNot(HaveOccurred())
			Expect(serverErr).ToNot(HaveOccurred())
		})

		It("performs a HelloRetryRequst", func() {
			serverConf.CurvePreferences = []tls.CurveID{tls.CurveP384}
			_, _, clientErr, _, _, serverErr := handshakeWithTLSConf(
				clientConf, serverConf,
				&utils.RTTStats{}, &utils.RTTStats{},
				&wire.TransportParameters{ActiveConnectionIDLimit: 2}, &wire.TransportParameters{ActiveConnectionIDLimit: 2},
				false,
			)
			Expect(clientErr).ToNot(HaveOccurred())
			Expect(serverErr).ToNot(HaveOccurred())
		})

		It("handshakes with client auth", func() {
			clientConf.Certificates = []tls.Certificate{generateCert()}
			serverConf.ClientAuth = tls.RequireAnyClientCert
			_, _, clientErr, _, _, serverErr := handshakeWithTLSConf(
				clientConf, serverConf,
				&utils.RTTStats{}, &utils.RTTStats{},
				&wire.TransportParameters{ActiveConnectionIDLimit: 2}, &wire.TransportParameters{ActiveConnectionIDLimit: 2},
				false,
			)
			Expect(clientErr).ToNot(HaveOccurred())
			Expect(serverErr).ToNot(HaveOccurred())
		})

		It("receives transport parameters", func() {
			cTransportParameters := &wire.TransportParameters{ActiveConnectionIDLimit: 2, MaxIdleTimeout: 42 * time.Second}
			client := NewCryptoSetupClient(
				protocol.ConnectionID{},
				cTransportParameters,
				clientConf,
				false,
				&utils.RTTStats{},
				nil,
				utils.DefaultLogger.WithPrefix("client"),
				protocol.Version1,
			)

			var token protocol.StatelessResetToken
			sTransportParameters := &wire.TransportParameters{
				MaxIdleTimeout:          1337 * time.Second,
				StatelessResetToken:     &token,
				ActiveConnectionIDLimit: 2,
			}
			server := NewCryptoSetupServer(
				protocol.ConnectionID{},
				&net.UDPAddr{IP: net.IPv6loopback, Port: 1234},
				&net.UDPAddr{IP: net.IPv6loopback, Port: 4321},
				sTransportParameters,
				serverConf,
				false,
				&utils.RTTStats{},
				nil,
				utils.DefaultLogger.WithPrefix("server"),
				protocol.Version1,
			)

			clientEvents, cErr, serverEvents, sErr := handshake(client, server)
			Expect(cErr).ToNot(HaveOccurred())
			Expect(sErr).ToNot(HaveOccurred())
			var clientReceivedTransportParameters *wire.TransportParameters
			for _, ev := range clientEvents {
				if ev.Kind == EventReceivedTransportParameters {
					clientReceivedTransportParameters = ev.TransportParameters
				}
			}
			Expect(clientReceivedTransportParameters).ToNot(BeNil())
			Expect(clientReceivedTransportParameters.MaxIdleTimeout).To(Equal(1337 * time.Second))

			var serverReceivedTransportParameters *wire.TransportParameters
			for _, ev := range serverEvents {
				if ev.Kind == EventReceivedTransportParameters {
					serverReceivedTransportParameters = ev.TransportParameters
				}
			}
			Expect(serverReceivedTransportParameters).ToNot(BeNil())
			Expect(serverReceivedTransportParameters.MaxIdleTimeout).To(Equal(42 * time.Second))
		})

		Context("with session tickets", func() {
			It("errors when the NewSessionTicket is sent at the wrong encryption level", func() {
				client, _, clientErr, _, _, serverErr := handshakeWithTLSConf(
					clientConf, serverConf,
					&utils.RTTStats{}, &utils.RTTStats{},
					&wire.TransportParameters{ActiveConnectionIDLimit: 2}, &wire.TransportParameters{ActiveConnectionIDLimit: 2},
					false,
				)
				Expect(clientErr).ToNot(HaveOccurred())
				Expect(serverErr).ToNot(HaveOccurred())

				// inject an invalid session ticket
				b := append([]byte{uint8(typeNewSessionTicket), 0, 0, 6}, []byte("foobar")...)
				err := client.HandleMessage(b, protocol.EncryptionHandshake)
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("tls: handshake data received at wrong level"))
			})

			It("errors when handling the NewSessionTicket fails", func() {
				client, _, clientErr, _, _, serverErr := handshakeWithTLSConf(
					clientConf, serverConf,
					&utils.RTTStats{}, &utils.RTTStats{},
					&wire.TransportParameters{ActiveConnectionIDLimit: 2}, &wire.TransportParameters{ActiveConnectionIDLimit: 2},
					false,
				)
				Expect(clientErr).ToNot(HaveOccurred())
				Expect(serverErr).ToNot(HaveOccurred())

				// inject an invalid session ticket
				b := append([]byte{uint8(typeNewSessionTicket), 0, 0, 6}, []byte("foobar")...)
				err := client.HandleMessage(b, protocol.Encryption1RTT)
				Expect(err).To(BeAssignableToTypeOf(&qerr.TransportError{}))
				Expect(err.(*qerr.TransportError).ErrorCode.IsCryptoError()).To(BeTrue())
			})

			It("uses session resumption", func() {
				csc := mocktls.NewMockClientSessionCache(mockCtrl)
				var state *tls.ClientSessionState
				receivedSessionTicket := make(chan struct{})
				csc.EXPECT().Get(gomock.Any())
				csc.EXPECT().Put(gomock.Any(), gomock.Any()).Do(func(_ string, css *tls.ClientSessionState) {
					state = css
					close(receivedSessionTicket)
				})
				clientConf.ClientSessionCache = csc
				const clientRTT = 30 * time.Millisecond // RTT as measured by the client. Should be restored.
				clientOrigRTTStats := newRTTStatsWithRTT(clientRTT)
				client, _, clientErr, server, _, serverErr := handshakeWithTLSConf(
					clientConf, serverConf,
					clientOrigRTTStats, &utils.RTTStats{},
					&wire.TransportParameters{ActiveConnectionIDLimit: 2}, &wire.TransportParameters{ActiveConnectionIDLimit: 2},
					false,
				)
				Expect(clientErr).ToNot(HaveOccurred())
				Expect(serverErr).ToNot(HaveOccurred())
				Eventually(receivedSessionTicket).Should(BeClosed())
				Expect(server.ConnectionState().DidResume).To(BeFalse())
				Expect(client.ConnectionState().DidResume).To(BeFalse())

				csc.EXPECT().Get(gomock.Any()).Return(state, true)
				csc.EXPECT().Put(gomock.Any(), gomock.Any()).MaxTimes(1)
				clientRTTStats := &utils.RTTStats{}
				client, _, clientErr, server, _, serverErr = handshakeWithTLSConf(
					clientConf, serverConf,
					clientRTTStats, &utils.RTTStats{},
					&wire.TransportParameters{ActiveConnectionIDLimit: 2}, &wire.TransportParameters{ActiveConnectionIDLimit: 2},
					false,
				)
				Expect(clientErr).ToNot(HaveOccurred())
				Expect(serverErr).ToNot(HaveOccurred())
				Eventually(receivedSessionTicket).Should(BeClosed())
				Expect(server.ConnectionState().DidResume).To(BeTrue())
				Expect(client.ConnectionState().DidResume).To(BeTrue())
				Expect(clientRTTStats.SmoothedRTT()).To(Equal(clientRTT))
			})

			It("doesn't use session resumption if the server disabled it", func() {
				csc := mocktls.NewMockClientSessionCache(mockCtrl)
				var state *tls.ClientSessionState
				receivedSessionTicket := make(chan struct{})
				csc.EXPECT().Get(gomock.Any())
				csc.EXPECT().Put(gomock.Any(), gomock.Any()).Do(func(_ string, css *tls.ClientSessionState) {
					state = css
					close(receivedSessionTicket)
				})
				clientConf.ClientSessionCache = csc
				client, _, clientErr, server, _, serverErr := handshakeWithTLSConf(
					clientConf, serverConf,
					&utils.RTTStats{}, &utils.RTTStats{},
					&wire.TransportParameters{ActiveConnectionIDLimit: 2}, &wire.TransportParameters{ActiveConnectionIDLimit: 2},
					false,
				)
				Expect(clientErr).ToNot(HaveOccurred())
				Expect(serverErr).ToNot(HaveOccurred())
				Eventually(receivedSessionTicket).Should(BeClosed())
				Expect(server.ConnectionState().DidResume).To(BeFalse())
				Expect(client.ConnectionState().DidResume).To(BeFalse())

				serverConf.SessionTicketsDisabled = true
				csc.EXPECT().Get(gomock.Any()).Return(state, true)
				client, _, clientErr, server, _, serverErr = handshakeWithTLSConf(
					clientConf, serverConf,
					&utils.RTTStats{}, &utils.RTTStats{},
					&wire.TransportParameters{ActiveConnectionIDLimit: 2}, &wire.TransportParameters{ActiveConnectionIDLimit: 2},
					false,
				)
				Expect(clientErr).ToNot(HaveOccurred())
				Expect(serverErr).ToNot(HaveOccurred())
				Eventually(receivedSessionTicket).Should(BeClosed())
				Expect(server.ConnectionState().DidResume).To(BeFalse())
				Expect(client.ConnectionState().DidResume).To(BeFalse())
			})

			It("uses 0-RTT", func() {
				csc := mocktls.NewMockClientSessionCache(mockCtrl)
				var state *tls.ClientSessionState
				receivedSessionTicket := make(chan struct{})
				csc.EXPECT().Get(gomock.Any())
				csc.EXPECT().Put(gomock.Any(), gomock.Any()).Do(func(_ string, css *tls.ClientSessionState) {
					state = css
					close(receivedSessionTicket)
				})
				clientConf.ClientSessionCache = csc
				const serverRTT = 25 * time.Millisecond // RTT as measured by the server. Should be restored.
				const clientRTT = 30 * time.Millisecond // RTT as measured by the client. Should be restored.
				serverOrigRTTStats := newRTTStatsWithRTT(serverRTT)
				clientOrigRTTStats := newRTTStatsWithRTT(clientRTT)
				const initialMaxData protocol.ByteCount = 1337
				client, _, clientErr, server, _, serverErr := handshakeWithTLSConf(
					clientConf, serverConf,
					clientOrigRTTStats, serverOrigRTTStats,
					&wire.TransportParameters{ActiveConnectionIDLimit: 2},
					&wire.TransportParameters{ActiveConnectionIDLimit: 2, InitialMaxData: initialMaxData},
					true,
				)
				Expect(clientErr).ToNot(HaveOccurred())
				Expect(serverErr).ToNot(HaveOccurred())
				Eventually(receivedSessionTicket).Should(BeClosed())
				Expect(server.ConnectionState().DidResume).To(BeFalse())
				Expect(client.ConnectionState().DidResume).To(BeFalse())

				csc.EXPECT().Get(gomock.Any()).Return(state, true)
				csc.EXPECT().Put(gomock.Any(), gomock.Any()).MaxTimes(1)

				clientRTTStats := &utils.RTTStats{}
				serverRTTStats := &utils.RTTStats{}
				client, clientEvents, clientErr, server, serverEvents, serverErr := handshakeWithTLSConf(
					clientConf, serverConf,
					clientRTTStats, serverRTTStats,
					&wire.TransportParameters{ActiveConnectionIDLimit: 2},
					&wire.TransportParameters{ActiveConnectionIDLimit: 2, InitialMaxData: initialMaxData},
					true,
				)
				Expect(clientErr).ToNot(HaveOccurred())
				Expect(serverErr).ToNot(HaveOccurred())
				Expect(clientRTTStats.SmoothedRTT()).To(Equal(clientRTT))
				Expect(serverRTTStats.SmoothedRTT()).To(Equal(serverRTT))

				var tp *wire.TransportParameters
				var clientReceived0RTTKeys bool
				for _, ev := range clientEvents {
					//nolint:exhaustive // only need to process a few events
					switch ev.Kind {
					case EventRestoredTransportParameters:
						tp = ev.TransportParameters
					case EventReceivedReadKeys:
						clientReceived0RTTKeys = true
					}
				}
				Expect(clientReceived0RTTKeys).To(BeTrue())
				Expect(tp).ToNot(BeNil())
				Expect(tp.InitialMaxData).To(Equal(initialMaxData))

				var serverReceived0RTTKeys bool
				for _, ev := range serverEvents {
					//nolint:exhaustive // only need to process a few events
					switch ev.Kind {
					case EventReceivedReadKeys:
						serverReceived0RTTKeys = true
					}
				}
				Expect(serverReceived0RTTKeys).To(BeTrue())

				Expect(server.ConnectionState().DidResume).To(BeTrue())
				Expect(client.ConnectionState().DidResume).To(BeTrue())
				Expect(server.ConnectionState().Used0RTT).To(BeTrue())
				Expect(client.ConnectionState().Used0RTT).To(BeTrue())
			})

			It("rejects 0-RTT, when the transport parameters changed", func() {
				csc := mocktls.NewMockClientSessionCache(mockCtrl)
				var state *tls.ClientSessionState
				receivedSessionTicket := make(chan struct{})
				csc.EXPECT().Get(gomock.Any())
				csc.EXPECT().Put(gomock.Any(), gomock.Any()).Do(func(_ string, css *tls.ClientSessionState) {
					state = css
					close(receivedSessionTicket)
				})
				clientConf.ClientSessionCache = csc
				const clientRTT = 30 * time.Millisecond // RTT as measured by the client. Should be restored.
				clientOrigRTTStats := newRTTStatsWithRTT(clientRTT)
				const initialMaxData protocol.ByteCount = 1337
				client, _, clientErr, server, _, serverErr := handshakeWithTLSConf(
					clientConf, serverConf,
					clientOrigRTTStats, &utils.RTTStats{},
					&wire.TransportParameters{ActiveConnectionIDLimit: 2},
					&wire.TransportParameters{ActiveConnectionIDLimit: 2, InitialMaxData: initialMaxData},
					true,
				)
				Expect(clientErr).ToNot(HaveOccurred())
				Expect(serverErr).ToNot(HaveOccurred())
				Eventually(receivedSessionTicket).Should(BeClosed())
				Expect(server.ConnectionState().DidResume).To(BeFalse())
				Expect(client.ConnectionState().DidResume).To(BeFalse())

				csc.EXPECT().Get(gomock.Any()).Return(state, true)
				csc.EXPECT().Put(gomock.Any(), gomock.Any()).MaxTimes(1)

				clientRTTStats := &utils.RTTStats{}
				client, clientEvents, clientErr, server, _, serverErr := handshakeWithTLSConf(
					clientConf, serverConf,
					clientRTTStats, &utils.RTTStats{},
					&wire.TransportParameters{ActiveConnectionIDLimit: 2},
					&wire.TransportParameters{ActiveConnectionIDLimit: 2, InitialMaxData: initialMaxData - 1},
					true,
				)
				Expect(clientErr).ToNot(HaveOccurred())
				Expect(serverErr).ToNot(HaveOccurred())
				Expect(clientRTTStats.SmoothedRTT()).To(Equal(clientRTT))

				var tp *wire.TransportParameters
				var clientReceived0RTTKeys bool
				for _, ev := range clientEvents {
					//nolint:exhaustive // only need to process a few events
					switch ev.Kind {
					case EventRestoredTransportParameters:
						tp = ev.TransportParameters
					case EventReceivedReadKeys:
						clientReceived0RTTKeys = true
					}
				}
				Expect(clientReceived0RTTKeys).To(BeTrue())
				Expect(tp).ToNot(BeNil())
				Expect(tp.InitialMaxData).To(Equal(initialMaxData))

				Expect(server.ConnectionState().DidResume).To(BeTrue())
				Expect(client.ConnectionState().DidResume).To(BeTrue())
				Expect(server.ConnectionState().Used0RTT).To(BeFalse())
				Expect(client.ConnectionState().Used0RTT).To(BeFalse())
			})
		})
	})
})
