package handshake

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io/ioutil"
	"math/big"
	"time"

	gomock "github.com/golang/mock/gomock"
	"github.com/lucas-clemente/quic-go/internal/congestion"
	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/qerr"
	"github.com/lucas-clemente/quic-go/internal/testdata"
	"github.com/lucas-clemente/quic-go/internal/utils"
	"github.com/marten-seemann/qtls"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
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

	initStreams := func() (chan chunk, *stream /* initial */, *stream /* handshake */, *stream /* 1-RTT */) {
		chunkChan := make(chan chunk, 100)
		initialStream := newStream(chunkChan, protocol.EncryptionInitial)
		handshakeStream := newStream(chunkChan, protocol.EncryptionHandshake)
		oneRTTStream := newStream(chunkChan, protocol.Encryption1RTT)
		return chunkChan, initialStream, handshakeStream, oneRTTStream
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

	It("creates a qtls.Config", func() {
		tlsConf := &tls.Config{
			ServerName: "quic.clemente.io",
			GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
				return nil, errors.New("GetCertificate")
			},
			GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
				return nil, errors.New("GetClientCertificate")
			},
			GetConfigForClient: func(ch *tls.ClientHelloInfo) (*tls.Config, error) {
				return &tls.Config{ServerName: ch.ServerName}, nil
			},
		}
		server := NewCryptoSetupServer(
			&bytes.Buffer{},
			&bytes.Buffer{},
			ioutil.Discard,
			protocol.ConnectionID{},
			nil,
			&TransportParameters{},
			NewMockHandshakeRunner(mockCtrl),
			tlsConf,
			&congestion.RTTStats{},
			utils.DefaultLogger.WithPrefix("server"),
		)
		qtlsConf := server.(*cryptoSetup).tlsConf
		Expect(qtlsConf.ServerName).To(Equal(tlsConf.ServerName))
		_, getCertificateErr := qtlsConf.GetCertificate(nil)
		Expect(getCertificateErr).To(MatchError("GetCertificate"))
		_, getClientCertificateErr := qtlsConf.GetClientCertificate(nil)
		Expect(getClientCertificateErr).To(MatchError("GetClientCertificate"))
		cconf, err := qtlsConf.GetConfigForClient(&tls.ClientHelloInfo{ServerName: "foo.bar"})
		Expect(err).ToNot(HaveOccurred())
		Expect(cconf.ServerName).To(Equal("foo.bar"))
		Expect(cconf.AlternativeRecordLayer).ToNot(BeNil())
		Expect(cconf.GetExtensions).ToNot(BeNil())
		Expect(cconf.ReceivedExtensions).ToNot(BeNil())
	})

	It("returns Handshake() when an error occurs in qtls", func() {
		sErrChan := make(chan error, 1)
		runner := NewMockHandshakeRunner(mockCtrl)
		runner.EXPECT().OnError(gomock.Any()).Do(func(e error) { sErrChan <- e })
		_, sInitialStream, sHandshakeStream, _ := initStreams()
		server := NewCryptoSetupServer(
			sInitialStream,
			sHandshakeStream,
			ioutil.Discard,
			protocol.ConnectionID{},
			nil,
			&TransportParameters{},
			runner,
			testdata.GetTLSConfig(),
			&congestion.RTTStats{},
			utils.DefaultLogger.WithPrefix("server"),
		)

		done := make(chan struct{})
		go func() {
			defer GinkgoRecover()
			server.RunHandshake()
			Expect(sErrChan).To(Receive(MatchError("CRYPTO_ERROR: local error: tls: unexpected message")))
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

	It("errors when a message is received at the wrong encryption level", func() {
		sErrChan := make(chan error, 1)
		_, sInitialStream, sHandshakeStream, _ := initStreams()
		runner := NewMockHandshakeRunner(mockCtrl)
		runner.EXPECT().OnError(gomock.Any()).Do(func(e error) { sErrChan <- e })
		server := NewCryptoSetupServer(
			sInitialStream,
			sHandshakeStream,
			ioutil.Discard,
			protocol.ConnectionID{},
			nil,
			&TransportParameters{},
			runner,
			testdata.GetTLSConfig(),
			&congestion.RTTStats{},
			utils.DefaultLogger.WithPrefix("server"),
		)

		done := make(chan struct{})
		go func() {
			defer GinkgoRecover()
			server.RunHandshake()
			close(done)
		}()

		fakeCH := append([]byte{byte(typeClientHello), 0, 0, 6}, []byte("foobar")...)
		server.HandleMessage(fakeCH, protocol.EncryptionHandshake) // wrong encryption level
		var err error
		Expect(sErrChan).To(Receive(&err))
		Expect(err).To(BeAssignableToTypeOf(&qerr.QuicError{}))
		qerr := err.(*qerr.QuicError)
		Expect(qerr.IsCryptoError()).To(BeTrue())
		Expect(qerr.ErrorCode).To(BeEquivalentTo(0x100 + int(alertUnexpectedMessage)))
		Expect(err.Error()).To(ContainSubstring("expected handshake message ClientHello to have encryption level Initial, has Handshake"))

		// make the go routine return
		Expect(server.Close()).To(Succeed())
		Eventually(done).Should(BeClosed())
	})

	It("returns Handshake() when handling a message fails", func() {
		sErrChan := make(chan error, 1)
		_, sInitialStream, sHandshakeStream, _ := initStreams()
		runner := NewMockHandshakeRunner(mockCtrl)
		runner.EXPECT().OnError(gomock.Any()).Do(func(e error) { sErrChan <- e })
		server := NewCryptoSetupServer(
			sInitialStream,
			sHandshakeStream,
			ioutil.Discard,
			protocol.ConnectionID{},
			nil,
			&TransportParameters{},
			runner,
			serverConf,
			&congestion.RTTStats{},
			utils.DefaultLogger.WithPrefix("server"),
		)

		done := make(chan struct{})
		go func() {
			defer GinkgoRecover()
			server.RunHandshake()
			var err error
			Expect(sErrChan).To(Receive(&err))
			Expect(err).To(BeAssignableToTypeOf(&qerr.QuicError{}))
			qerr := err.(*qerr.QuicError)
			Expect(qerr.IsCryptoError()).To(BeTrue())
			Expect(qerr.ErrorCode).To(BeEquivalentTo(0x100 + int(alertUnexpectedMessage)))
			close(done)
		}()

		fakeCH := append([]byte{byte(typeServerHello), 0, 0, 6}, []byte("foobar")...)
		server.HandleMessage(fakeCH, protocol.EncryptionInitial) // wrong encryption level
		Eventually(done).Should(BeClosed())
	})

	It("returns Handshake() when it is closed", func() {
		_, sInitialStream, sHandshakeStream, _ := initStreams()
		server := NewCryptoSetupServer(
			sInitialStream,
			sHandshakeStream,
			ioutil.Discard,
			protocol.ConnectionID{},
			nil,
			&TransportParameters{},
			NewMockHandshakeRunner(mockCtrl),
			serverConf,
			&congestion.RTTStats{},
			utils.DefaultLogger.WithPrefix("server"),
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
		var testDone chan struct{}

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

		BeforeEach(func() {
			testDone = make(chan struct{})
		})

		AfterEach(func() {
			close(testDone)
		})

		handshake := func(client CryptoSetup, cChunkChan <-chan chunk,
			server CryptoSetup, sChunkChan <-chan chunk) {
			done := make(chan struct{})
			go func() {
				defer GinkgoRecover()
				for {
					select {
					case c := <-cChunkChan:
						server.HandleMessage(c.data, c.encLevel)
					case c := <-sChunkChan:
						client.HandleMessage(c.data, c.encLevel)
					case <-testDone: // handshake complete
						return
					}
				}
			}()

			go func() {
				defer GinkgoRecover()
				server.RunHandshake()
				close(done)
			}()

			client.RunHandshake()
			Eventually(done).Should(BeClosed())
		}

		handshakeWithTLSConf := func(clientConf, serverConf *tls.Config) (CryptoSetup /* client */, error /* client error */, CryptoSetup /* server */, error /* server error */) {
			var cHandshakeComplete bool
			cChunkChan, cInitialStream, cHandshakeStream, cOneRTTStream := initStreams()
			cErrChan := make(chan error, 1)
			cRunner := NewMockHandshakeRunner(mockCtrl)
			cRunner.EXPECT().OnReceivedParams(gomock.Any())
			cRunner.EXPECT().OnError(gomock.Any()).Do(func(e error) { cErrChan <- e }).MaxTimes(1)
			cRunner.EXPECT().OnHandshakeComplete().Do(func() { cHandshakeComplete = true }).MaxTimes(1)
			client, _ := NewCryptoSetupClient(
				cInitialStream,
				cHandshakeStream,
				cOneRTTStream,
				protocol.ConnectionID{},
				nil,
				&TransportParameters{},
				cRunner,
				clientConf,
				&congestion.RTTStats{},
				utils.DefaultLogger.WithPrefix("client"),
			)

			var sHandshakeComplete bool
			sChunkChan, sInitialStream, sHandshakeStream, sOneRTTStream := initStreams()
			sErrChan := make(chan error, 1)
			sRunner := NewMockHandshakeRunner(mockCtrl)
			sRunner.EXPECT().OnReceivedParams(gomock.Any())
			sRunner.EXPECT().OnError(gomock.Any()).Do(func(e error) { sErrChan <- e }).MaxTimes(1)
			sRunner.EXPECT().OnHandshakeComplete().Do(func() { sHandshakeComplete = true }).MaxTimes(1)
			var token [16]byte
			server := NewCryptoSetupServer(
				sInitialStream,
				sHandshakeStream,
				sOneRTTStream,
				protocol.ConnectionID{},
				nil,
				&TransportParameters{StatelessResetToken: &token},
				sRunner,
				serverConf,
				&congestion.RTTStats{},
				utils.DefaultLogger.WithPrefix("server"),
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
			return client, cErr, server, sErr
		}

		It("handshakes", func() {
			_, clientErr, _, serverErr := handshakeWithTLSConf(clientConf, serverConf)
			Expect(clientErr).ToNot(HaveOccurred())
			Expect(serverErr).ToNot(HaveOccurred())
		})

		It("performs a HelloRetryRequst", func() {
			serverConf.CurvePreferences = []tls.CurveID{tls.CurveP384}
			_, clientErr, _, serverErr := handshakeWithTLSConf(clientConf, serverConf)
			Expect(clientErr).ToNot(HaveOccurred())
			Expect(serverErr).ToNot(HaveOccurred())
		})

		It("handshakes with client auth", func() {
			clientConf.Certificates = []tls.Certificate{generateCert()}
			serverConf.ClientAuth = qtls.RequireAnyClientCert
			_, clientErr, _, serverErr := handshakeWithTLSConf(clientConf, serverConf)
			Expect(clientErr).ToNot(HaveOccurred())
			Expect(serverErr).ToNot(HaveOccurred())
		})

		It("signals when it has written the ClientHello", func() {
			runner := NewMockHandshakeRunner(mockCtrl)
			cChunkChan, cInitialStream, cHandshakeStream, _ := initStreams()
			client, chChan := NewCryptoSetupClient(
				cInitialStream,
				cHandshakeStream,
				ioutil.Discard,
				protocol.ConnectionID{},
				nil,
				&TransportParameters{},
				runner,
				&tls.Config{InsecureSkipVerify: true},
				&congestion.RTTStats{},
				utils.DefaultLogger.WithPrefix("client"),
			)

			done := make(chan struct{})
			go func() {
				defer GinkgoRecover()
				client.RunHandshake()
				close(done)
			}()
			var ch chunk
			Eventually(cChunkChan).Should(Receive(&ch))
			Eventually(chChan).Should(BeClosed())
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
			var cTransportParametersRcvd, sTransportParametersRcvd []byte
			cChunkChan, cInitialStream, cHandshakeStream, _ := initStreams()
			cTransportParameters := &TransportParameters{IdleTimeout: 0x42 * time.Second}
			cRunner := NewMockHandshakeRunner(mockCtrl)
			cRunner.EXPECT().OnReceivedParams(gomock.Any()).Do(func(b []byte) { sTransportParametersRcvd = b })
			cRunner.EXPECT().OnHandshakeComplete()
			client, _ := NewCryptoSetupClient(
				cInitialStream,
				cHandshakeStream,
				ioutil.Discard,
				protocol.ConnectionID{},
				nil,
				cTransportParameters,
				cRunner,
				clientConf,
				&congestion.RTTStats{},
				utils.DefaultLogger.WithPrefix("client"),
			)

			sChunkChan, sInitialStream, sHandshakeStream, _ := initStreams()
			var token [16]byte
			sRunner := NewMockHandshakeRunner(mockCtrl)
			sRunner.EXPECT().OnReceivedParams(gomock.Any()).Do(func(b []byte) { cTransportParametersRcvd = b })
			sRunner.EXPECT().OnHandshakeComplete()
			sTransportParameters := &TransportParameters{
				IdleTimeout:         0x1337 * time.Second,
				StatelessResetToken: &token,
			}
			server := NewCryptoSetupServer(
				sInitialStream,
				sHandshakeStream,
				ioutil.Discard,
				protocol.ConnectionID{},
				nil,
				sTransportParameters,
				sRunner,
				serverConf,
				&congestion.RTTStats{},
				utils.DefaultLogger.WithPrefix("server"),
			)

			done := make(chan struct{})
			go func() {
				defer GinkgoRecover()
				handshake(client, cChunkChan, server, sChunkChan)
				close(done)
			}()
			Eventually(done).Should(BeClosed())
			Expect(cTransportParametersRcvd).ToNot(BeNil())
			clTP := &TransportParameters{}
			Expect(clTP.Unmarshal(cTransportParametersRcvd, protocol.PerspectiveClient)).To(Succeed())
			Expect(clTP.IdleTimeout).To(Equal(cTransportParameters.IdleTimeout))
			Expect(sTransportParametersRcvd).ToNot(BeNil())
			srvTP := &TransportParameters{}
			Expect(srvTP.Unmarshal(sTransportParametersRcvd, protocol.PerspectiveServer)).To(Succeed())
			Expect(srvTP.IdleTimeout).To(Equal(sTransportParameters.IdleTimeout))
		})

		Context("with session tickets", func() {
			It("errors when the NewSessionTicket is sent at the wrong encryption level", func() {
				cChunkChan, cInitialStream, cHandshakeStream, _ := initStreams()
				cRunner := NewMockHandshakeRunner(mockCtrl)
				cRunner.EXPECT().OnReceivedParams(gomock.Any())
				cRunner.EXPECT().OnHandshakeComplete()
				client, _ := NewCryptoSetupClient(
					cInitialStream,
					cHandshakeStream,
					ioutil.Discard,
					protocol.ConnectionID{},
					nil,
					&TransportParameters{},
					cRunner,
					clientConf,
					&congestion.RTTStats{},
					utils.DefaultLogger.WithPrefix("client"),
				)

				sChunkChan, sInitialStream, sHandshakeStream, _ := initStreams()
				sRunner := NewMockHandshakeRunner(mockCtrl)
				sRunner.EXPECT().OnReceivedParams(gomock.Any())
				sRunner.EXPECT().OnHandshakeComplete()
				server := NewCryptoSetupServer(
					sInitialStream,
					sHandshakeStream,
					ioutil.Discard,
					protocol.ConnectionID{},
					nil,
					&TransportParameters{},
					sRunner,
					serverConf,
					&congestion.RTTStats{},
					utils.DefaultLogger.WithPrefix("server"),
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
					Expect(err).To(BeAssignableToTypeOf(&qerr.QuicError{}))
					qerr := err.(*qerr.QuicError)
					Expect(qerr.IsCryptoError()).To(BeTrue())
					Expect(qerr.ErrorCode).To(BeEquivalentTo(0x100 + int(alertUnexpectedMessage)))
					Expect(qerr.Error()).To(ContainSubstring("expected handshake message NewSessionTicket to have encryption level 1-RTT, has Handshake"))
				})
				b := append([]byte{uint8(typeNewSessionTicket), 0, 0, 6}, []byte("foobar")...)
				client.HandleMessage(b, protocol.EncryptionHandshake)
			})

			It("errors when handling the NewSessionTicket fails", func() {
				cChunkChan, cInitialStream, cHandshakeStream, _ := initStreams()
				cRunner := NewMockHandshakeRunner(mockCtrl)
				cRunner.EXPECT().OnReceivedParams(gomock.Any())
				cRunner.EXPECT().OnHandshakeComplete()
				client, _ := NewCryptoSetupClient(
					cInitialStream,
					cHandshakeStream,
					ioutil.Discard,
					protocol.ConnectionID{},
					nil,
					&TransportParameters{},
					cRunner,
					clientConf,
					&congestion.RTTStats{},
					utils.DefaultLogger.WithPrefix("client"),
				)

				sChunkChan, sInitialStream, sHandshakeStream, _ := initStreams()
				sRunner := NewMockHandshakeRunner(mockCtrl)
				sRunner.EXPECT().OnReceivedParams(gomock.Any())
				sRunner.EXPECT().OnHandshakeComplete()
				server := NewCryptoSetupServer(
					sInitialStream,
					sHandshakeStream,
					ioutil.Discard,
					protocol.ConnectionID{},
					nil,
					&TransportParameters{},
					sRunner,
					serverConf,
					&congestion.RTTStats{},
					utils.DefaultLogger.WithPrefix("server"),
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
					Expect(err).To(BeAssignableToTypeOf(&qerr.QuicError{}))
					qerr := err.(*qerr.QuicError)
					Expect(qerr.IsCryptoError()).To(BeTrue())
				})
				b := append([]byte{uint8(typeNewSessionTicket), 0, 0, 6}, []byte("foobar")...)
				client.HandleMessage(b, protocol.Encryption1RTT)
			})

			It("uses session resumption", func() {
				csc := NewMockClientSessionCache(mockCtrl)
				var state *tls.ClientSessionState
				receivedSessionTicket := make(chan struct{})
				csc.EXPECT().Get(gomock.Any())
				csc.EXPECT().Put(gomock.Any(), gomock.Any()).Do(func(_ string, css *tls.ClientSessionState) {
					state = css
					close(receivedSessionTicket)
				})
				clientConf.ClientSessionCache = csc
				client, clientErr, server, serverErr := handshakeWithTLSConf(clientConf, serverConf)
				Expect(clientErr).ToNot(HaveOccurred())
				Expect(serverErr).ToNot(HaveOccurred())
				Eventually(receivedSessionTicket).Should(BeClosed())
				Expect(server.ConnectionState().DidResume).To(BeFalse())
				Expect(client.ConnectionState().DidResume).To(BeFalse())

				csc.EXPECT().Get(gomock.Any()).Return(state, true)
				csc.EXPECT().Put(gomock.Any(), gomock.Any()).MaxTimes(1)
				client, clientErr, server, serverErr = handshakeWithTLSConf(clientConf, serverConf)
				Expect(clientErr).ToNot(HaveOccurred())
				Expect(serverErr).ToNot(HaveOccurred())
				Eventually(receivedSessionTicket).Should(BeClosed())
				Expect(server.ConnectionState().DidResume).To(BeTrue())
				Expect(client.ConnectionState().DidResume).To(BeTrue())
			})

			It("doesn't use session resumption if the server disabled it", func() {
				csc := NewMockClientSessionCache(mockCtrl)
				var state *tls.ClientSessionState
				receivedSessionTicket := make(chan struct{})
				csc.EXPECT().Get(gomock.Any())
				csc.EXPECT().Put(gomock.Any(), gomock.Any()).Do(func(_ string, css *tls.ClientSessionState) {
					state = css
					close(receivedSessionTicket)
				})
				clientConf.ClientSessionCache = csc
				client, clientErr, server, serverErr := handshakeWithTLSConf(clientConf, serverConf)
				Expect(clientErr).ToNot(HaveOccurred())
				Expect(serverErr).ToNot(HaveOccurred())
				Eventually(receivedSessionTicket).Should(BeClosed())
				Expect(server.ConnectionState().DidResume).To(BeFalse())
				Expect(client.ConnectionState().DidResume).To(BeFalse())

				serverConf.SessionTicketsDisabled = true
				csc.EXPECT().Get(gomock.Any()).Return(state, true)
				client, clientErr, server, serverErr = handshakeWithTLSConf(clientConf, serverConf)
				Expect(clientErr).ToNot(HaveOccurred())
				Expect(serverErr).ToNot(HaveOccurred())
				Eventually(receivedSessionTicket).Should(BeClosed())
				Expect(server.ConnectionState().DidResume).To(BeFalse())
				Expect(client.ConnectionState().DidResume).To(BeFalse())
			})
		})
	})
})
