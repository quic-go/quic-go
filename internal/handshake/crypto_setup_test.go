package handshake

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io/ioutil"
	"math/big"
	"time"

	"github.com/lucas-clemente/quic-go/internal/protocol"
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
	var clientConf *tls.Config

	initStreams := func() (chan chunk, *stream /* initial */, *stream /* handshake */) {
		chunkChan := make(chan chunk, 100)
		initialStream := newStream(chunkChan, protocol.EncryptionInitial)
		handshakeStream := newStream(chunkChan, protocol.EncryptionHandshake)
		return chunkChan, initialStream, handshakeStream
	}

	BeforeEach(func() {
		clientConf = &tls.Config{
			ServerName: "localhost",
			RootCAs:    testdata.GetRootCA(),
		}
	})

	It("returns Handshake() when an error occurs", func() {
		_, sInitialStream, sHandshakeStream := initStreams()
		server, err := NewCryptoSetupServer(
			sInitialStream,
			sHandshakeStream,
			ioutil.Discard,
			protocol.ConnectionID{},
			&EncryptedExtensionsTransportParameters{
				NegotiatedVersion: protocol.VersionTLS,
				SupportedVersions: []protocol.VersionNumber{protocol.VersionTLS},
			},
			func([]byte) {},
			testdata.GetTLSConfig(),
			utils.DefaultLogger.WithPrefix("server"),
		)
		Expect(err).ToNot(HaveOccurred())

		done := make(chan struct{})
		go func() {
			defer GinkgoRecover()
			err := server.RunHandshake()
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("received unexpected handshake message"))
			close(done)
		}()

		fakeCH := append([]byte{byte(typeClientHello), 0, 0, 6}, []byte("foobar")...)
		server.HandleMessage(fakeCH, protocol.EncryptionInitial)
		Eventually(done).Should(BeClosed())
	})

	It("returns Handshake() when handling a message fails", func() {
		_, sInitialStream, sHandshakeStream := initStreams()
		server, err := NewCryptoSetupServer(
			sInitialStream,
			sHandshakeStream,
			ioutil.Discard,
			protocol.ConnectionID{},
			&EncryptedExtensionsTransportParameters{
				NegotiatedVersion: protocol.VersionTLS,
				SupportedVersions: []protocol.VersionNumber{protocol.VersionTLS},
			},
			func([]byte) {},
			testdata.GetTLSConfig(),
			utils.DefaultLogger.WithPrefix("server"),
		)
		Expect(err).ToNot(HaveOccurred())

		done := make(chan struct{})
		go func() {
			defer GinkgoRecover()
			err := server.RunHandshake()
			Expect(err).To(MatchError("expected handshake message ClientHello to have encryption level Initial, has Handshake"))
			close(done)
		}()

		fakeCH := append([]byte{byte(typeClientHello), 0, 0, 6}, []byte("foobar")...)
		server.HandleMessage(fakeCH, protocol.EncryptionHandshake) // wrong encryption level
		Eventually(done).Should(BeClosed())
	})

	It("returns Handshake() when it is closed", func() {
		_, sInitialStream, sHandshakeStream := initStreams()
		server, err := NewCryptoSetupServer(
			sInitialStream,
			sHandshakeStream,
			ioutil.Discard,
			protocol.ConnectionID{},
			&EncryptedExtensionsTransportParameters{
				NegotiatedVersion: protocol.VersionTLS,
				SupportedVersions: []protocol.VersionNumber{protocol.VersionTLS},
			},
			func([]byte) {},
			testdata.GetTLSConfig(),
			utils.DefaultLogger.WithPrefix("server"),
		)
		Expect(err).ToNot(HaveOccurred())

		done := make(chan struct{})
		go func() {
			defer GinkgoRecover()
			err := server.RunHandshake()
			Expect(err).To(MatchError("Handshake aborted"))
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

		handshake := func(
			client CryptoSetup,
			cChunkChan <-chan chunk,
			server CryptoSetup,
			sChunkChan <-chan chunk) (error /* client error */, error /* server error */) {
			done := make(chan struct{})
			defer close(done)
			go func() {
				defer GinkgoRecover()
				for {
					select {
					case c := <-cChunkChan:
						server.HandleMessage(c.data, c.encLevel)
					case c := <-sChunkChan:
						client.HandleMessage(c.data, c.encLevel)
					case <-done: // handshake complete
						return
					}
				}
			}()

			serverErrChan := make(chan error)
			go func() {
				defer GinkgoRecover()
				serverErrChan <- server.RunHandshake()
			}()

			clientErr := client.RunHandshake()
			var serverErr error
			Eventually(serverErrChan).Should(Receive(&serverErr))
			return clientErr, serverErr
		}

		handshakeWithTLSConf := func(clientConf, serverConf *tls.Config) (error /* client error */, error /* server error */) {
			cChunkChan, cInitialStream, cHandshakeStream := initStreams()
			client, _, err := NewCryptoSetupClient(
				cInitialStream,
				cHandshakeStream,
				ioutil.Discard,
				protocol.ConnectionID{},
				&ClientHelloTransportParameters{
					InitialVersion: protocol.VersionTLS,
				},
				func([]byte) {},
				clientConf,
				utils.DefaultLogger.WithPrefix("client"),
			)
			Expect(err).ToNot(HaveOccurred())

			sChunkChan, sInitialStream, sHandshakeStream := initStreams()
			server, err := NewCryptoSetupServer(
				sInitialStream,
				sHandshakeStream,
				ioutil.Discard,
				protocol.ConnectionID{},
				&EncryptedExtensionsTransportParameters{
					NegotiatedVersion: protocol.VersionTLS,
					SupportedVersions: []protocol.VersionNumber{protocol.VersionTLS},
					Parameters:        TransportParameters{StatelessResetToken: bytes.Repeat([]byte{42}, 16)},
				},
				func([]byte) {},
				serverConf,
				utils.DefaultLogger.WithPrefix("server"),
			)
			Expect(err).ToNot(HaveOccurred())

			return handshake(client, cChunkChan, server, sChunkChan)
		}

		It("handshakes", func() {
			serverConf := testdata.GetTLSConfig()
			clientErr, serverErr := handshakeWithTLSConf(clientConf, serverConf)
			Expect(clientErr).ToNot(HaveOccurred())
			Expect(serverErr).ToNot(HaveOccurred())
		})

		It("handshakes with client auth", func() {
			clientConf.Certificates = []tls.Certificate{generateCert()}
			serverConf := testdata.GetTLSConfig()
			serverConf.ClientAuth = qtls.RequireAnyClientCert
			clientErr, serverErr := handshakeWithTLSConf(clientConf, serverConf)
			Expect(clientErr).ToNot(HaveOccurred())
			Expect(serverErr).ToNot(HaveOccurred())
		})

		It("signals when it has written the ClientHello", func() {
			cChunkChan, cInitialStream, cHandshakeStream := initStreams()
			client, chChan, err := NewCryptoSetupClient(
				cInitialStream,
				cHandshakeStream,
				ioutil.Discard,
				protocol.ConnectionID{},
				&ClientHelloTransportParameters{
					InitialVersion: protocol.VersionTLS,
				},
				func([]byte) {},
				&tls.Config{InsecureSkipVerify: true},
				utils.DefaultLogger.WithPrefix("client"),
			)
			Expect(err).ToNot(HaveOccurred())

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
			client.HandleMessage([]byte{42 /* unknown handshake message type */, 0, 0, 1, 0}, protocol.EncryptionInitial)
			Eventually(done).Should(BeClosed())
		})

		It("receives transport parameters", func() {
			var cTransportParametersRcvd, sTransportParametersRcvd []byte
			cChunkChan, cInitialStream, cHandshakeStream := initStreams()
			cTransportParameters := &TransportParameters{IdleTimeout: 0x42 * time.Second}
			client, _, err := NewCryptoSetupClient(
				cInitialStream,
				cHandshakeStream,
				ioutil.Discard,
				protocol.ConnectionID{},
				&ClientHelloTransportParameters{Parameters: *cTransportParameters},
				func(p []byte) { sTransportParametersRcvd = p },
				clientConf,
				utils.DefaultLogger.WithPrefix("client"),
			)
			Expect(err).ToNot(HaveOccurred())

			sChunkChan, sInitialStream, sHandshakeStream := initStreams()
			sTransportParameters := &TransportParameters{
				IdleTimeout:         0x1337 * time.Second,
				StatelessResetToken: bytes.Repeat([]byte{42}, 16),
			}
			server, err := NewCryptoSetupServer(
				sInitialStream,
				sHandshakeStream,
				ioutil.Discard,
				protocol.ConnectionID{},
				&EncryptedExtensionsTransportParameters{Parameters: *sTransportParameters},
				func(p []byte) { cTransportParametersRcvd = p },
				testdata.GetTLSConfig(),
				utils.DefaultLogger.WithPrefix("server"),
			)
			Expect(err).ToNot(HaveOccurred())

			done := make(chan struct{})
			go func() {
				defer GinkgoRecover()
				clientErr, serverErr := handshake(client, cChunkChan, server, sChunkChan)
				Expect(clientErr).ToNot(HaveOccurred())
				Expect(serverErr).ToNot(HaveOccurred())
				close(done)
			}()
			Eventually(done).Should(BeClosed())
			Expect(cTransportParametersRcvd).ToNot(BeNil())
			chtp := &ClientHelloTransportParameters{}
			Expect(chtp.Unmarshal(cTransportParametersRcvd)).To(Succeed())
			Expect(chtp.Parameters.IdleTimeout).To(Equal(cTransportParameters.IdleTimeout))
			Expect(sTransportParametersRcvd).ToNot(BeNil())
			eetp := &EncryptedExtensionsTransportParameters{}
			Expect(eetp.Unmarshal(sTransportParametersRcvd)).To(Succeed())
			Expect(eetp.Parameters.IdleTimeout).To(Equal(sTransportParameters.IdleTimeout))
		})
	})
})
