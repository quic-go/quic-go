package handshake

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
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

type chunk struct {
	data     []byte
	encLevel protocol.EncryptionLevel
}

type stream struct {
	encLevel  protocol.EncryptionLevel
	chunkChan chan<- chunk
}

func newStream(chunkChan chan<- chunk, encLevel protocol.EncryptionLevel) *stream {
	return &stream{
		chunkChan: chunkChan,
		encLevel:  encLevel,
	}
}

func (s *stream) Write(b []byte) (int, error) {
	data := make([]byte, len(b))
	copy(data, b)
	select {
	case s.chunkChan <- chunk{data: data, encLevel: s.encLevel}:
	default:
		panic("chunkChan too small")
	}
	return len(b), nil
}

var _ = Describe("Crypto Setup TLS", func() {
	var clientConf, serverConf *tls.Config

	// unparam incorrectly complains that the first argument is never used.
	//nolint:unparam
	initStreams := func() (chan chunk, *stream /* initial */, *stream /* handshake */) {
		chunkChan := make(chan chunk, 100)
		initialStream := newStream(chunkChan, protocol.EncryptionInitial)
		handshakeStream := newStream(chunkChan, protocol.EncryptionHandshake)
		return chunkChan, initialStream, handshakeStream
	}

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
		_, sInitialStream, sHandshakeStream := initStreams()
		tlsConf := testdata.GetTLSConfig()
		tlsConf.InsecureSkipVerify = true
		tlsConf.NextProtos = []string{""}
		cl, _ := NewCryptoSetupClient(
			sInitialStream,
			sHandshakeStream,
			nil,
			protocol.ConnectionID{},
			&wire.TransportParameters{},
			NewMockHandshakeRunner(mockCtrl),
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
		_, sInitialStream, sHandshakeStream := initStreams()
		runner := NewMockHandshakeRunner(mockCtrl)
		var token protocol.StatelessResetToken
		server := NewCryptoSetupServer(
			sInitialStream,
			sHandshakeStream,
			nil,
			protocol.ConnectionID{},
			&wire.TransportParameters{StatelessResetToken: &token},
			runner,
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

		handshake := func(client CryptoSetup, cChunkChan <-chan chunk, server CryptoSetup, sChunkChan <-chan chunk) {
			Expect(client.StartHandshake()).To(Succeed())
			Expect(server.StartHandshake()).To(Succeed())

			for {
				select {
				case c := <-cChunkChan:
					Expect(server.HandleMessage(c.data, c.encLevel)).To(Succeed())
					continue
				default:
				}
				select {
				case c := <-sChunkChan:
					Expect(client.HandleMessage(c.data, c.encLevel)).To(Succeed())
					continue
				default:
				}
				// no more messages to send from client and server. Handshake complete?
				break
			}

			ticket, err := server.GetSessionTicket()
			Expect(err).ToNot(HaveOccurred())
			if ticket != nil {
				Expect(client.HandleMessage(ticket, protocol.Encryption1RTT)).To(Succeed())
			}
		}

		handshakeWithTLSConf := func(
			clientConf, serverConf *tls.Config,
			clientRTTStats, serverRTTStats *utils.RTTStats,
			clientTransportParameters, serverTransportParameters *wire.TransportParameters,
			enable0RTT bool,
		) (<-chan *wire.TransportParameters /* clientHelloWrittenChan */, CryptoSetup /* client */, error /* client error */, CryptoSetup /* server */, error /* server error */) {
			var cHandshakeComplete bool
			cChunkChan, cInitialStream, cHandshakeStream := initStreams()
			cErrChan := make(chan error, 1)
			cRunner := NewMockHandshakeRunner(mockCtrl)
			cRunner.EXPECT().OnReceivedParams(gomock.Any())
			cRunner.EXPECT().OnReceivedReadKeys().MinTimes(2).MaxTimes(3) // 3 if using 0-RTT, 2 otherwise
			cRunner.EXPECT().OnHandshakeComplete().Do(func() { cHandshakeComplete = true }).MaxTimes(1)
			cRunner.EXPECT().DropKeys(gomock.Any()).MaxTimes(1)
			client, clientHelloWrittenChan := NewCryptoSetupClient(
				cInitialStream,
				cHandshakeStream,
				nil,
				protocol.ConnectionID{},
				clientTransportParameters,
				cRunner,
				clientConf,
				enable0RTT,
				clientRTTStats,
				nil,
				utils.DefaultLogger.WithPrefix("client"),
				protocol.Version1,
			)

			var sHandshakeComplete bool
			sChunkChan, sInitialStream, sHandshakeStream := initStreams()
			sErrChan := make(chan error, 1)
			sRunner := NewMockHandshakeRunner(mockCtrl)
			sRunner.EXPECT().OnReceivedParams(gomock.Any())
			sRunner.EXPECT().OnReceivedReadKeys().MinTimes(2).MaxTimes(3) // 3 if using 0-RTT, 2 otherwise
			sRunner.EXPECT().OnHandshakeComplete().Do(func() { sHandshakeComplete = true }).MaxTimes(1)
			if serverTransportParameters.StatelessResetToken == nil {
				var token protocol.StatelessResetToken
				serverTransportParameters.StatelessResetToken = &token
			}
			server := NewCryptoSetupServer(
				sInitialStream,
				sHandshakeStream,
				nil,
				protocol.ConnectionID{},
				serverTransportParameters,
				sRunner,
				serverConf,
				enable0RTT,
				serverRTTStats,
				nil,
				utils.DefaultLogger.WithPrefix("server"),
				protocol.Version1,
			)

			handshake(client, cChunkChan, server, sChunkChan)
			var cErr, sErr error
			select {
			case sErr = <-sErrChan:
			default:
				Expect(sHandshakeComplete).To(BeTrue())
			}
			select {
			case cErr = <-cErrChan:
			default:
				Expect(cHandshakeComplete).To(BeTrue())
			}
			return clientHelloWrittenChan, client, cErr, server, sErr
		}

		It("handshakes", func() {
			_, _, clientErr, _, serverErr := handshakeWithTLSConf(
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
			_, _, clientErr, _, serverErr := handshakeWithTLSConf(
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
			_, _, clientErr, _, serverErr := handshakeWithTLSConf(
				clientConf, serverConf,
				&utils.RTTStats{}, &utils.RTTStats{},
				&wire.TransportParameters{ActiveConnectionIDLimit: 2}, &wire.TransportParameters{ActiveConnectionIDLimit: 2},
				false,
			)
			Expect(clientErr).ToNot(HaveOccurred())
			Expect(serverErr).ToNot(HaveOccurred())
		})

		It("signals when it has written the ClientHello", func() {
			runner := NewMockHandshakeRunner(mockCtrl)
			cChunkChan, cInitialStream, cHandshakeStream := initStreams()
			client, chChan := NewCryptoSetupClient(
				cInitialStream,
				cHandshakeStream,
				nil,
				protocol.ConnectionID{},
				&wire.TransportParameters{},
				runner,
				&tls.Config{InsecureSkipVerify: true},
				false,
				&utils.RTTStats{},
				nil,
				utils.DefaultLogger.WithPrefix("client"),
				protocol.Version1,
			)

			Expect(client.StartHandshake()).To(Succeed())
			var ch chunk
			Eventually(cChunkChan).Should(Receive(&ch))
			Eventually(chChan).Should(Receive(BeNil()))
			// make sure the whole ClientHello was written
			Expect(len(ch.data)).To(BeNumerically(">=", 4))
			Expect(ch.data[0]).To(BeEquivalentTo(typeClientHello))
			length := int(ch.data[1])<<16 | int(ch.data[2])<<8 | int(ch.data[3])
			Expect(len(ch.data) - 4).To(Equal(length))
		})

		It("receives transport parameters", func() {
			var cTransportParametersRcvd, sTransportParametersRcvd *wire.TransportParameters
			cChunkChan, cInitialStream, cHandshakeStream := initStreams()
			cTransportParameters := &wire.TransportParameters{ActiveConnectionIDLimit: 2, MaxIdleTimeout: 0x42 * time.Second}
			cRunner := NewMockHandshakeRunner(mockCtrl)
			cRunner.EXPECT().OnReceivedReadKeys().Times(2)
			cRunner.EXPECT().OnReceivedParams(gomock.Any()).Do(func(tp *wire.TransportParameters) { sTransportParametersRcvd = tp })
			cRunner.EXPECT().OnHandshakeComplete()
			client, _ := NewCryptoSetupClient(
				cInitialStream,
				cHandshakeStream,
				nil,
				protocol.ConnectionID{},
				cTransportParameters,
				cRunner,
				clientConf,
				false,
				&utils.RTTStats{},
				nil,
				utils.DefaultLogger.WithPrefix("client"),
				protocol.Version1,
			)

			sChunkChan, sInitialStream, sHandshakeStream := initStreams()
			var token protocol.StatelessResetToken
			sRunner := NewMockHandshakeRunner(mockCtrl)
			sRunner.EXPECT().OnReceivedReadKeys().Times(2)
			sRunner.EXPECT().OnReceivedParams(gomock.Any()).Do(func(tp *wire.TransportParameters) { cTransportParametersRcvd = tp })
			sRunner.EXPECT().OnHandshakeComplete()
			sTransportParameters := &wire.TransportParameters{
				MaxIdleTimeout:          0x1337 * time.Second,
				StatelessResetToken:     &token,
				ActiveConnectionIDLimit: 2,
			}
			server := NewCryptoSetupServer(
				sInitialStream,
				sHandshakeStream,
				nil,
				protocol.ConnectionID{},
				sTransportParameters,
				sRunner,
				serverConf,
				false,
				&utils.RTTStats{},
				nil,
				utils.DefaultLogger.WithPrefix("server"),
				protocol.Version1,
			)

			done := make(chan struct{})
			go func() {
				defer GinkgoRecover()
				handshake(client, cChunkChan, server, sChunkChan)
				close(done)
			}()
			Eventually(done).Should(BeClosed())
			Expect(cTransportParametersRcvd.MaxIdleTimeout).To(Equal(cTransportParameters.MaxIdleTimeout))
			Expect(sTransportParametersRcvd).ToNot(BeNil())
			Expect(sTransportParametersRcvd.MaxIdleTimeout).To(Equal(sTransportParameters.MaxIdleTimeout))
		})

		Context("with session tickets", func() {
			It("errors when the NewSessionTicket is sent at the wrong encryption level", func() {
				cChunkChan, cInitialStream, cHandshakeStream := initStreams()
				cRunner := NewMockHandshakeRunner(mockCtrl)
				cRunner.EXPECT().OnReceivedParams(gomock.Any())
				cRunner.EXPECT().OnReceivedReadKeys().Times(2)
				cRunner.EXPECT().OnHandshakeComplete()
				client, _ := NewCryptoSetupClient(
					cInitialStream,
					cHandshakeStream,
					nil,
					protocol.ConnectionID{},
					&wire.TransportParameters{ActiveConnectionIDLimit: 2},
					cRunner,
					clientConf,
					false,
					&utils.RTTStats{},
					nil,
					utils.DefaultLogger.WithPrefix("client"),
					protocol.Version1,
				)

				sChunkChan, sInitialStream, sHandshakeStream := initStreams()
				sRunner := NewMockHandshakeRunner(mockCtrl)
				sRunner.EXPECT().OnReceivedParams(gomock.Any())
				sRunner.EXPECT().OnReceivedReadKeys().Times(2)
				sRunner.EXPECT().OnHandshakeComplete()
				var token protocol.StatelessResetToken
				server := NewCryptoSetupServer(
					sInitialStream,
					sHandshakeStream,
					nil,
					protocol.ConnectionID{},
					&wire.TransportParameters{ActiveConnectionIDLimit: 2, StatelessResetToken: &token},
					sRunner,
					serverConf,
					false,
					&utils.RTTStats{},
					nil,
					utils.DefaultLogger.WithPrefix("server"),
					protocol.Version1,
				)

				done := make(chan struct{})
				go func() {
					defer GinkgoRecover()
					handshake(client, cChunkChan, server, sChunkChan)
					close(done)
				}()
				Eventually(done).Should(BeClosed())

				// inject an invalid session ticket
				b := append([]byte{uint8(typeNewSessionTicket), 0, 0, 6}, []byte("foobar")...)
				err := client.HandleMessage(b, protocol.EncryptionHandshake)
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("tls: handshake data received at wrong level"))
			})

			It("errors when handling the NewSessionTicket fails", func() {
				cChunkChan, cInitialStream, cHandshakeStream := initStreams()
				cRunner := NewMockHandshakeRunner(mockCtrl)
				cRunner.EXPECT().OnReceivedParams(gomock.Any())
				cRunner.EXPECT().OnReceivedReadKeys().Times(2)
				cRunner.EXPECT().OnHandshakeComplete()
				client, _ := NewCryptoSetupClient(
					cInitialStream,
					cHandshakeStream,
					nil,
					protocol.ConnectionID{},
					&wire.TransportParameters{ActiveConnectionIDLimit: 2},
					cRunner,
					clientConf,
					false,
					&utils.RTTStats{},
					nil,
					utils.DefaultLogger.WithPrefix("client"),
					protocol.Version1,
				)

				sChunkChan, sInitialStream, sHandshakeStream := initStreams()
				sRunner := NewMockHandshakeRunner(mockCtrl)
				sRunner.EXPECT().OnReceivedParams(gomock.Any())
				sRunner.EXPECT().OnReceivedReadKeys().Times(2)
				sRunner.EXPECT().OnHandshakeComplete()
				var token protocol.StatelessResetToken
				server := NewCryptoSetupServer(
					sInitialStream,
					sHandshakeStream,
					nil,
					protocol.ConnectionID{},
					&wire.TransportParameters{ActiveConnectionIDLimit: 2, StatelessResetToken: &token},
					sRunner,
					serverConf,
					false,
					&utils.RTTStats{},
					nil,
					utils.DefaultLogger.WithPrefix("server"),
					protocol.Version1,
				)

				done := make(chan struct{})
				go func() {
					defer GinkgoRecover()
					handshake(client, cChunkChan, server, sChunkChan)
					close(done)
				}()
				Eventually(done).Should(BeClosed())

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
				clientHelloWrittenChan, client, clientErr, server, serverErr := handshakeWithTLSConf(
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
				Expect(clientHelloWrittenChan).To(Receive(BeNil()))

				csc.EXPECT().Get(gomock.Any()).Return(state, true)
				csc.EXPECT().Put(gomock.Any(), gomock.Any()).MaxTimes(1)
				clientRTTStats := &utils.RTTStats{}
				clientHelloWrittenChan, client, clientErr, server, serverErr = handshakeWithTLSConf(
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
				Expect(clientHelloWrittenChan).To(Receive(BeNil()))
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
				_, client, clientErr, server, serverErr := handshakeWithTLSConf(
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
				_, client, clientErr, server, serverErr = handshakeWithTLSConf(
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
				clientHelloWrittenChan, client, clientErr, server, serverErr := handshakeWithTLSConf(
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
				Expect(clientHelloWrittenChan).To(Receive(BeNil()))

				csc.EXPECT().Get(gomock.Any()).Return(state, true)
				csc.EXPECT().Put(gomock.Any(), gomock.Any()).MaxTimes(1)

				clientRTTStats := &utils.RTTStats{}
				serverRTTStats := &utils.RTTStats{}
				clientHelloWrittenChan, client, clientErr, server, serverErr = handshakeWithTLSConf(
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
				Expect(clientHelloWrittenChan).To(Receive(&tp))
				Expect(tp.InitialMaxData).To(Equal(initialMaxData))

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
				clientHelloWrittenChan, client, clientErr, server, serverErr := handshakeWithTLSConf(
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
				Expect(clientHelloWrittenChan).To(Receive(BeNil()))

				csc.EXPECT().Get(gomock.Any()).Return(state, true)
				csc.EXPECT().Put(gomock.Any(), gomock.Any()).MaxTimes(1)

				clientRTTStats := &utils.RTTStats{}
				clientHelloWrittenChan, client, clientErr, server, serverErr = handshakeWithTLSConf(
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
				Expect(clientHelloWrittenChan).To(Receive(&tp))
				Expect(tp.InitialMaxData).To(Equal(initialMaxData))

				Expect(server.ConnectionState().DidResume).To(BeTrue())
				Expect(client.ConnectionState().DidResume).To(BeTrue())
				Expect(server.ConnectionState().Used0RTT).To(BeFalse())
				Expect(client.ConnectionState().Used0RTT).To(BeFalse())
			})
		})
	})
})
