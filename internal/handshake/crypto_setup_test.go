package handshake

import (
	"bytes"
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

var helloRetryRequestRandom = []byte{ // See RFC 8446, Section 4.1.3.
	0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11,
	0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
	0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E,
	0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C,
}

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

	It("returns Handshake() when an error occurs in qtls", func() {
		sErrChan := make(chan error, 1)
		runner := NewMockHandshakeRunner(mockCtrl)
		runner.EXPECT().OnError(gomock.Any()).Do(func(e error) { sErrChan <- e })
		_, sInitialStream, sHandshakeStream := initStreams()
		var token protocol.StatelessResetToken
		server := NewCryptoSetupServer(
			sInitialStream,
			sHandshakeStream,
			protocol.ConnectionID{},
			nil,
			nil,
			&wire.TransportParameters{StatelessResetToken: &token},
			runner,
			testdata.GetTLSConfig(),
			nil,
			&utils.RTTStats{},
			nil,
			utils.DefaultLogger.WithPrefix("server"),
			protocol.VersionTLS,
		)

		done := make(chan struct{})
		go func() {
			defer GinkgoRecover()
			server.RunHandshake()
			Expect(sErrChan).To(Receive(MatchError(&qerr.TransportError{
				ErrorCode:    0x100 + qerr.TransportErrorCode(alertUnexpectedMessage),
				ErrorMessage: "local error: tls: unexpected message",
			})))
			close(done)
		}()

		fakeCH := append([]byte{byte(typeClientHello), 0, 0, 6}, []byte("foobar")...)
		handledMessage := make(chan struct{})
		go func() {
			defer GinkgoRecover()
			server.HandleMessage(fakeCH, protocol.EncryptionInitial)
			close(handledMessage)
		}()
		Eventually(handledMessage).Should(BeClosed())
		Eventually(done).Should(BeClosed())
	})

	It("handles qtls errors occurring before during ClientHello generation", func() {
		sErrChan := make(chan error, 1)
		runner := NewMockHandshakeRunner(mockCtrl)
		runner.EXPECT().OnError(gomock.Any()).Do(func(e error) { sErrChan <- e })
		_, sInitialStream, sHandshakeStream := initStreams()
		tlsConf := testdata.GetTLSConfig()
		tlsConf.InsecureSkipVerify = true
		tlsConf.NextProtos = []string{""}
		cl, _ := NewCryptoSetupClient(
			sInitialStream,
			sHandshakeStream,
			protocol.ConnectionID{},
			nil,
			nil,
			&wire.TransportParameters{},
			runner,
			tlsConf,
			false,
			&utils.RTTStats{},
			nil,
			utils.DefaultLogger.WithPrefix("client"),
			protocol.VersionTLS,
		)

		done := make(chan struct{})
		go func() {
			defer GinkgoRecover()
			cl.RunHandshake()
			close(done)
		}()

		Eventually(done).Should(BeClosed())
		Expect(sErrChan).To(Receive(MatchError(&qerr.TransportError{
			ErrorCode:    qerr.InternalError,
			ErrorMessage: "tls: invalid NextProtos value",
		})))
	})

	It("errors when a message is received at the wrong encryption level", func() {
		sErrChan := make(chan error, 1)
		_, sInitialStream, sHandshakeStream := initStreams()
		runner := NewMockHandshakeRunner(mockCtrl)
		runner.EXPECT().OnError(gomock.Any()).Do(func(e error) { sErrChan <- e })
		var token protocol.StatelessResetToken
		server := NewCryptoSetupServer(
			sInitialStream,
			sHandshakeStream,
			protocol.ConnectionID{},
			nil,
			nil,
			&wire.TransportParameters{StatelessResetToken: &token},
			runner,
			testdata.GetTLSConfig(),
			nil,
			&utils.RTTStats{},
			nil,
			utils.DefaultLogger.WithPrefix("server"),
			protocol.VersionTLS,
		)

		done := make(chan struct{})
		go func() {
			defer GinkgoRecover()
			server.RunHandshake()
			close(done)
		}()

		fakeCH := append([]byte{byte(typeClientHello), 0, 0, 6}, []byte("foobar")...)
		server.HandleMessage(fakeCH, protocol.EncryptionHandshake) // wrong encryption level
		Expect(sErrChan).To(Receive(MatchError(&qerr.TransportError{
			ErrorCode:    0x100 + qerr.TransportErrorCode(alertUnexpectedMessage),
			ErrorMessage: "expected handshake message ClientHello to have encryption level Initial, has Handshake",
		})))

		// make the go routine return
		Expect(server.Close()).To(Succeed())
		Eventually(done).Should(BeClosed())
	})

	It("returns Handshake() when handling a message fails", func() {
		sErrChan := make(chan error, 1)
		_, sInitialStream, sHandshakeStream := initStreams()
		runner := NewMockHandshakeRunner(mockCtrl)
		runner.EXPECT().OnError(gomock.Any()).Do(func(e error) { sErrChan <- e })
		var token protocol.StatelessResetToken
		server := NewCryptoSetupServer(
			sInitialStream,
			sHandshakeStream,
			protocol.ConnectionID{},
			nil,
			nil,
			&wire.TransportParameters{StatelessResetToken: &token},
			runner,
			serverConf,
			nil,
			&utils.RTTStats{},
			nil,
			utils.DefaultLogger.WithPrefix("server"),
			protocol.VersionTLS,
		)

		done := make(chan struct{})
		go func() {
			defer GinkgoRecover()
			server.RunHandshake()
			var err error
			Expect(sErrChan).To(Receive(&err))
			Expect(err).To(BeAssignableToTypeOf(&qerr.TransportError{}))
			Expect(err.(*qerr.TransportError).ErrorCode).To(BeEquivalentTo(0x100 + int(alertUnexpectedMessage)))
			close(done)
		}()

		fakeCH := append([]byte{byte(typeServerHello), 0, 0, 6}, []byte("foobar")...)
		server.HandleMessage(fakeCH, protocol.EncryptionInitial) // wrong encryption level
		Eventually(done).Should(BeClosed())
	})

	It("returns Handshake() when it is closed", func() {
		_, sInitialStream, sHandshakeStream := initStreams()
		var token protocol.StatelessResetToken
		server := NewCryptoSetupServer(
			sInitialStream,
			sHandshakeStream,
			protocol.ConnectionID{},
			nil,
			nil,
			&wire.TransportParameters{StatelessResetToken: &token},
			NewMockHandshakeRunner(mockCtrl),
			serverConf,
			nil,
			&utils.RTTStats{},
			nil,
			utils.DefaultLogger.WithPrefix("server"),
			protocol.VersionTLS,
		)

		done := make(chan struct{})
		go func() {
			defer GinkgoRecover()
			server.RunHandshake()
			close(done)
		}()
		Expect(server.Close()).To(Succeed())
		Eventually(done).Should(BeClosed())
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

		handshake := func(client CryptoSetup, cChunkChan <-chan chunk,
			server CryptoSetup, sChunkChan <-chan chunk,
		) {
			done := make(chan struct{})
			go func() {
				defer GinkgoRecover()
				for {
					select {
					case c := <-cChunkChan:
						msgType := messageType(c.data[0])
						finished := server.HandleMessage(c.data, c.encLevel)
						if msgType == typeFinished {
							Expect(finished).To(BeTrue())
						} else if msgType == typeClientHello {
							// If this ClientHello didn't elicit a HelloRetryRequest, we're done with Initial keys.
							_, err := server.GetHandshakeOpener()
							Expect(finished).To(Equal(err == nil))
						} else {
							Expect(finished).To(BeFalse())
						}
					case c := <-sChunkChan:
						msgType := messageType(c.data[0])
						finished := client.HandleMessage(c.data, c.encLevel)
						if msgType == typeFinished {
							Expect(finished).To(BeTrue())
						} else if msgType == typeServerHello {
							Expect(finished).To(Equal(!bytes.Equal(c.data[6:6+32], helloRetryRequestRandom)))
						} else {
							Expect(finished).To(BeFalse())
						}
					case <-done: // handshake complete
						return
					}
				}
			}()

			go func() {
				defer GinkgoRecover()
				defer close(done)
				server.RunHandshake()
				ticket, err := server.GetSessionTicket()
				Expect(err).ToNot(HaveOccurred())
				if ticket != nil {
					client.HandleMessage(ticket, protocol.Encryption1RTT)
				}
			}()

			client.RunHandshake()
			Eventually(done).Should(BeClosed())
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
			cRunner.EXPECT().OnError(gomock.Any()).Do(func(e error) { cErrChan <- e }).MaxTimes(1)
			cRunner.EXPECT().OnHandshakeComplete().Do(func() { cHandshakeComplete = true }).MaxTimes(1)
			cRunner.EXPECT().DropKeys(gomock.Any()).MaxTimes(1)
			client, clientHelloWrittenChan := NewCryptoSetupClient(
				cInitialStream,
				cHandshakeStream,
				protocol.ConnectionID{},
				nil,
				nil,
				clientTransportParameters,
				cRunner,
				clientConf,
				enable0RTT,
				clientRTTStats,
				nil,
				utils.DefaultLogger.WithPrefix("client"),
				protocol.VersionTLS,
			)

			var allow0RTT func() bool
			if enable0RTT {
				allow0RTT = func() bool { return true }
			}
			var sHandshakeComplete bool
			sChunkChan, sInitialStream, sHandshakeStream := initStreams()
			sErrChan := make(chan error, 1)
			sRunner := NewMockHandshakeRunner(mockCtrl)
			sRunner.EXPECT().OnReceivedParams(gomock.Any())
			sRunner.EXPECT().OnError(gomock.Any()).Do(func(e error) { sErrChan <- e }).MaxTimes(1)
			sRunner.EXPECT().OnHandshakeComplete().Do(func() { sHandshakeComplete = true }).MaxTimes(1)
			if serverTransportParameters.StatelessResetToken == nil {
				var token protocol.StatelessResetToken
				serverTransportParameters.StatelessResetToken = &token
			}
			server := NewCryptoSetupServer(
				sInitialStream,
				sHandshakeStream,
				protocol.ConnectionID{},
				nil,
				nil,
				serverTransportParameters,
				sRunner,
				serverConf,
				allow0RTT,
				serverRTTStats,
				nil,
				utils.DefaultLogger.WithPrefix("server"),
				protocol.VersionTLS,
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
				protocol.ConnectionID{},
				nil,
				nil,
				&wire.TransportParameters{},
				runner,
				&tls.Config{InsecureSkipVerify: true},
				false,
				&utils.RTTStats{},
				nil,
				utils.DefaultLogger.WithPrefix("client"),
				protocol.VersionTLS,
			)

			done := make(chan struct{})
			go func() {
				defer GinkgoRecover()
				client.RunHandshake()
				close(done)
			}()
			var ch chunk
			Eventually(cChunkChan).Should(Receive(&ch))
			Eventually(chChan).Should(Receive(BeNil()))
			// make sure the whole ClientHello was written
			Expect(len(ch.data)).To(BeNumerically(">=", 4))
			Expect(messageType(ch.data[0])).To(Equal(typeClientHello))
			length := int(ch.data[1])<<16 | int(ch.data[2])<<8 | int(ch.data[3])
			Expect(len(ch.data) - 4).To(Equal(length))

			// make the go routine return
			Expect(client.Close()).To(Succeed())
			Eventually(done).Should(BeClosed())
		})

		It("receives transport parameters", func() {
			var cTransportParametersRcvd, sTransportParametersRcvd *wire.TransportParameters
			cChunkChan, cInitialStream, cHandshakeStream := initStreams()
			cTransportParameters := &wire.TransportParameters{ActiveConnectionIDLimit: 2, MaxIdleTimeout: 0x42 * time.Second}
			cRunner := NewMockHandshakeRunner(mockCtrl)
			cRunner.EXPECT().OnReceivedParams(gomock.Any()).Do(func(tp *wire.TransportParameters) { sTransportParametersRcvd = tp })
			cRunner.EXPECT().OnHandshakeComplete()
			client, _ := NewCryptoSetupClient(
				cInitialStream,
				cHandshakeStream,
				protocol.ConnectionID{},
				nil,
				nil,
				cTransportParameters,
				cRunner,
				clientConf,
				false,
				&utils.RTTStats{},
				nil,
				utils.DefaultLogger.WithPrefix("client"),
				protocol.VersionTLS,
			)

			sChunkChan, sInitialStream, sHandshakeStream := initStreams()
			var token protocol.StatelessResetToken
			sRunner := NewMockHandshakeRunner(mockCtrl)
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
				protocol.ConnectionID{},
				nil,
				nil,
				sTransportParameters,
				sRunner,
				serverConf,
				nil,
				&utils.RTTStats{},
				nil,
				utils.DefaultLogger.WithPrefix("server"),
				protocol.VersionTLS,
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
				cRunner.EXPECT().OnHandshakeComplete()
				client, _ := NewCryptoSetupClient(
					cInitialStream,
					cHandshakeStream,
					protocol.ConnectionID{},
					nil,
					nil,
					&wire.TransportParameters{ActiveConnectionIDLimit: 2},
					cRunner,
					clientConf,
					false,
					&utils.RTTStats{},
					nil,
					utils.DefaultLogger.WithPrefix("client"),
					protocol.VersionTLS,
				)

				sChunkChan, sInitialStream, sHandshakeStream := initStreams()
				sRunner := NewMockHandshakeRunner(mockCtrl)
				sRunner.EXPECT().OnReceivedParams(gomock.Any())
				sRunner.EXPECT().OnHandshakeComplete()
				var token protocol.StatelessResetToken
				server := NewCryptoSetupServer(
					sInitialStream,
					sHandshakeStream,
					protocol.ConnectionID{},
					nil,
					nil,
					&wire.TransportParameters{ActiveConnectionIDLimit: 2, StatelessResetToken: &token},
					sRunner,
					serverConf,
					nil,
					&utils.RTTStats{},
					nil,
					utils.DefaultLogger.WithPrefix("server"),
					protocol.VersionTLS,
				)

				done := make(chan struct{})
				go func() {
					defer GinkgoRecover()
					handshake(client, cChunkChan, server, sChunkChan)
					close(done)
				}()
				Eventually(done).Should(BeClosed())

				// inject an invalid session ticket
				cRunner.EXPECT().OnError(&qerr.TransportError{
					ErrorCode:    0x100 + qerr.TransportErrorCode(alertUnexpectedMessage),
					ErrorMessage: "expected handshake message NewSessionTicket to have encryption level 1-RTT, has Handshake",
				})
				b := append([]byte{uint8(typeNewSessionTicket), 0, 0, 6}, []byte("foobar")...)
				client.HandleMessage(b, protocol.EncryptionHandshake)
			})

			It("errors when handling the NewSessionTicket fails", func() {
				cChunkChan, cInitialStream, cHandshakeStream := initStreams()
				cRunner := NewMockHandshakeRunner(mockCtrl)
				cRunner.EXPECT().OnReceivedParams(gomock.Any())
				cRunner.EXPECT().OnHandshakeComplete()
				client, _ := NewCryptoSetupClient(
					cInitialStream,
					cHandshakeStream,
					protocol.ConnectionID{},
					nil,
					nil,
					&wire.TransportParameters{ActiveConnectionIDLimit: 2},
					cRunner,
					clientConf,
					false,
					&utils.RTTStats{},
					nil,
					utils.DefaultLogger.WithPrefix("client"),
					protocol.VersionTLS,
				)

				sChunkChan, sInitialStream, sHandshakeStream := initStreams()
				sRunner := NewMockHandshakeRunner(mockCtrl)
				sRunner.EXPECT().OnReceivedParams(gomock.Any())
				sRunner.EXPECT().OnHandshakeComplete()
				var token protocol.StatelessResetToken
				server := NewCryptoSetupServer(
					sInitialStream,
					sHandshakeStream,
					protocol.ConnectionID{},
					nil,
					nil,
					&wire.TransportParameters{ActiveConnectionIDLimit: 2, StatelessResetToken: &token},
					sRunner,
					serverConf,
					nil,
					&utils.RTTStats{},
					nil,
					utils.DefaultLogger.WithPrefix("server"),
					protocol.VersionTLS,
				)

				done := make(chan struct{})
				go func() {
					defer GinkgoRecover()
					handshake(client, cChunkChan, server, sChunkChan)
					close(done)
				}()
				Eventually(done).Should(BeClosed())

				// inject an invalid session ticket
				cRunner.EXPECT().OnError(gomock.Any()).Do(func(err error) {
					Expect(err).To(BeAssignableToTypeOf(&qerr.TransportError{}))
					Expect(err.(*qerr.TransportError).ErrorCode.IsCryptoError()).To(BeTrue())
				})
				b := append([]byte{uint8(typeNewSessionTicket), 0, 0, 6}, []byte("foobar")...)
				client.HandleMessage(b, protocol.Encryption1RTT)
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
				csc.EXPECT().Put(gomock.Any(), nil)
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
				csc.EXPECT().Put(gomock.Any(), nil)
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
