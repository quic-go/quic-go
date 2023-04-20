package quic

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"time"

	mocklogging "github.com/quic-go/quic-go/internal/mocks/logging"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/utils"
	"github.com/quic-go/quic-go/logging"

	"github.com/golang/mock/gomock"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

type nullMultiplexer struct{}

func (n nullMultiplexer) AddConn(indexableConn)          {}
func (n nullMultiplexer) RemoveConn(indexableConn) error { return nil }

var _ = Describe("Client", func() {
	var (
		cl              *client
		packetConn      *MockPacketConn
		addr            net.Addr
		connID          protocol.ConnectionID
		origMultiplexer multiplexer
		tlsConf         *tls.Config
		tracer          *mocklogging.MockConnectionTracer
		config          *Config

		originalClientConnConstructor func(
			conn sendConn,
			runner connRunner,
			destConnID protocol.ConnectionID,
			srcConnID protocol.ConnectionID,
			connIDGenerator ConnectionIDGenerator,
			conf *Config,
			tlsConf *tls.Config,
			initialPacketNumber protocol.PacketNumber,
			enable0RTT bool,
			hasNegotiatedVersion bool,
			tracer logging.ConnectionTracer,
			tracingID uint64,
			logger utils.Logger,
			v protocol.VersionNumber,
		) quicConn
	)

	BeforeEach(func() {
		tlsConf = &tls.Config{NextProtos: []string{"proto1"}}
		connID = protocol.ParseConnectionID([]byte{0, 0, 0, 0, 0, 0, 0x13, 0x37})
		originalClientConnConstructor = newClientConnection
		tracer = mocklogging.NewMockConnectionTracer(mockCtrl)
		tr := mocklogging.NewMockTracer(mockCtrl)
		tr.EXPECT().DroppedPacket(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes()
		tr.EXPECT().TracerForConnection(gomock.Any(), protocol.PerspectiveClient, gomock.Any()).Return(tracer).MaxTimes(1)
		config = &Config{Tracer: tr, Versions: []protocol.VersionNumber{protocol.Version1}}
		Eventually(areConnsRunning).Should(BeFalse())
		addr = &net.UDPAddr{IP: net.IPv4(192, 168, 100, 200), Port: 1337}
		packetConn = NewMockPacketConn(mockCtrl)
		packetConn.EXPECT().LocalAddr().Return(&net.UDPAddr{}).AnyTimes()
		cl = &client{
			srcConnID:  connID,
			destConnID: connID,
			version:    protocol.Version1,
			sconn:      newSendPconn(packetConn, addr),
			tracer:     tracer,
			logger:     utils.DefaultLogger,
		}
		getMultiplexer() // make the sync.Once execute
		// replace the clientMuxer. getMultiplexer will now return the nullMultiplexer
		origMultiplexer = connMuxer
		connMuxer = &nullMultiplexer{}
	})

	AfterEach(func() {
		connMuxer = origMultiplexer
		newClientConnection = originalClientConnConstructor
	})

	AfterEach(func() {
		if s, ok := cl.conn.(*connection); ok {
			s.shutdown()
		}
		Eventually(areConnsRunning).Should(BeFalse())
	})

	Context("Dialing", func() {
		var origGenerateConnectionIDForInitial func() (protocol.ConnectionID, error)

		BeforeEach(func() {
			origGenerateConnectionIDForInitial = generateConnectionIDForInitial
			generateConnectionIDForInitial = func() (protocol.ConnectionID, error) {
				return connID, nil
			}
		})

		AfterEach(func() {
			generateConnectionIDForInitial = origGenerateConnectionIDForInitial
		})

		It("returns after the handshake is complete", func() {
			manager := NewMockPacketHandlerManager(mockCtrl)
			manager.EXPECT().Add(gomock.Any(), gomock.Any())

			run := make(chan struct{})
			newClientConnection = func(
				_ sendConn,
				_ connRunner,
				_ protocol.ConnectionID,
				_ protocol.ConnectionID,
				_ ConnectionIDGenerator,
				_ *Config,
				_ *tls.Config,
				_ protocol.PacketNumber,
				enable0RTT bool,
				_ bool,
				_ logging.ConnectionTracer,
				_ uint64,
				_ utils.Logger,
				_ protocol.VersionNumber,
			) quicConn {
				Expect(enable0RTT).To(BeFalse())
				conn := NewMockQUICConn(mockCtrl)
				conn.EXPECT().run().Do(func() { close(run) })
				c := make(chan struct{})
				close(c)
				conn.EXPECT().HandshakeComplete().Return(c)
				return conn
			}
			cl, err := newClient(packetConn, addr, &protocol.DefaultConnectionIDGenerator{}, populateConfig(config), tlsConf, nil, false, false)
			Expect(err).ToNot(HaveOccurred())
			cl.packetHandlers = manager
			Expect(cl).ToNot(BeNil())
			Expect(cl.dial(context.Background())).To(Succeed())
			Eventually(run).Should(BeClosed())
		})

		It("returns early connections", func() {
			manager := NewMockPacketHandlerManager(mockCtrl)
			manager.EXPECT().Add(gomock.Any(), gomock.Any())
			readyChan := make(chan struct{})
			done := make(chan struct{})
			newClientConnection = func(
				_ sendConn,
				runner connRunner,
				_ protocol.ConnectionID,
				_ protocol.ConnectionID,
				_ ConnectionIDGenerator,
				_ *Config,
				_ *tls.Config,
				_ protocol.PacketNumber,
				enable0RTT bool,
				_ bool,
				_ logging.ConnectionTracer,
				_ uint64,
				_ utils.Logger,
				_ protocol.VersionNumber,
			) quicConn {
				Expect(enable0RTT).To(BeTrue())
				conn := NewMockQUICConn(mockCtrl)
				conn.EXPECT().run().Do(func() { close(done) })
				conn.EXPECT().HandshakeComplete().Return(make(chan struct{}))
				conn.EXPECT().earlyConnReady().Return(readyChan)
				return conn
			}

			cl, err := newClient(packetConn, addr, &protocol.DefaultConnectionIDGenerator{}, populateConfig(config), tlsConf, nil, true, false)
			Expect(err).ToNot(HaveOccurred())
			cl.packetHandlers = manager
			Expect(cl).ToNot(BeNil())
			Expect(cl.dial(context.Background())).To(Succeed())
			Eventually(done).Should(BeClosed())
		})

		It("returns an error that occurs while waiting for the handshake to complete", func() {
			manager := NewMockPacketHandlerManager(mockCtrl)
			manager.EXPECT().Add(gomock.Any(), gomock.Any())

			testErr := errors.New("early handshake error")
			newClientConnection = func(
				_ sendConn,
				_ connRunner,
				_ protocol.ConnectionID,
				_ protocol.ConnectionID,
				_ ConnectionIDGenerator,
				_ *Config,
				_ *tls.Config,
				_ protocol.PacketNumber,
				_ bool,
				_ bool,
				_ logging.ConnectionTracer,
				_ uint64,
				_ utils.Logger,
				_ protocol.VersionNumber,
			) quicConn {
				conn := NewMockQUICConn(mockCtrl)
				conn.EXPECT().run().Return(testErr)
				conn.EXPECT().HandshakeComplete().Return(make(chan struct{}))
				conn.EXPECT().earlyConnReady().Return(make(chan struct{}))
				return conn
			}
			var closed bool
			cl, err := newClient(packetConn, addr, &protocol.DefaultConnectionIDGenerator{}, populateConfig(config), tlsConf, func() { closed = true }, true, false)
			Expect(err).ToNot(HaveOccurred())
			cl.packetHandlers = manager
			Expect(cl).ToNot(BeNil())
			Expect(cl.dial(context.Background())).To(MatchError(testErr))
			Expect(closed).To(BeTrue())
		})

		Context("quic.Config", func() {
			It("setups with the right values", func() {
				tokenStore := NewLRUTokenStore(10, 4)
				config := &Config{
					HandshakeIdleTimeout:  1337 * time.Minute,
					MaxIdleTimeout:        42 * time.Hour,
					MaxIncomingStreams:    1234,
					MaxIncomingUniStreams: 4321,
					TokenStore:            tokenStore,
					EnableDatagrams:       true,
				}
				c := populateConfig(config)
				Expect(c.HandshakeIdleTimeout).To(Equal(1337 * time.Minute))
				Expect(c.MaxIdleTimeout).To(Equal(42 * time.Hour))
				Expect(c.MaxIncomingStreams).To(BeEquivalentTo(1234))
				Expect(c.MaxIncomingUniStreams).To(BeEquivalentTo(4321))
				Expect(c.TokenStore).To(Equal(tokenStore))
				Expect(c.EnableDatagrams).To(BeTrue())
			})

			It("disables bidirectional streams", func() {
				config := &Config{
					MaxIncomingStreams:    -1,
					MaxIncomingUniStreams: 4321,
				}
				c := populateConfig(config)
				Expect(c.MaxIncomingStreams).To(BeZero())
				Expect(c.MaxIncomingUniStreams).To(BeEquivalentTo(4321))
			})

			It("disables unidirectional streams", func() {
				config := &Config{
					MaxIncomingStreams:    1234,
					MaxIncomingUniStreams: -1,
				}
				c := populateConfig(config)
				Expect(c.MaxIncomingStreams).To(BeEquivalentTo(1234))
				Expect(c.MaxIncomingUniStreams).To(BeZero())
			})

			It("fills in default values if options are not set in the Config", func() {
				c := populateConfig(&Config{})
				Expect(c.Versions).To(Equal(protocol.SupportedVersions))
				Expect(c.HandshakeIdleTimeout).To(Equal(protocol.DefaultHandshakeIdleTimeout))
				Expect(c.MaxIdleTimeout).To(Equal(protocol.DefaultIdleTimeout))
			})
		})

		It("creates new connections with the right parameters", func() {
			config := &Config{Versions: []protocol.VersionNumber{protocol.Version1}}
			c := make(chan struct{})
			var cconn sendConn
			var version protocol.VersionNumber
			var conf *Config
			done := make(chan struct{})
			newClientConnection = func(
				connP sendConn,
				_ connRunner,
				_ protocol.ConnectionID,
				_ protocol.ConnectionID,
				_ ConnectionIDGenerator,
				configP *Config,
				_ *tls.Config,
				_ protocol.PacketNumber,
				_ bool,
				_ bool,
				_ logging.ConnectionTracer,
				_ uint64,
				_ utils.Logger,
				versionP protocol.VersionNumber,
			) quicConn {
				cconn = connP
				version = versionP
				conf = configP
				close(c)
				// TODO: check connection IDs?
				conn := NewMockQUICConn(mockCtrl)
				conn.EXPECT().run()
				conn.EXPECT().HandshakeComplete().Return(make(chan struct{}))
				conn.EXPECT().destroy(gomock.Any())
				close(done)
				return conn
			}
			packetConn.EXPECT().ReadFrom(gomock.Any()).DoAndReturn(func([]byte) (int, net.Addr, error) {
				<-done
				return 0, nil, errors.New("closed")
			})
			packetConn.EXPECT().SetReadDeadline(gomock.Any()).AnyTimes()
			_, err := Dial(context.Background(), packetConn, addr, tlsConf, config)
			Expect(err).ToNot(HaveOccurred())
			Eventually(c).Should(BeClosed())
			Expect(cconn.(*spconn).PacketConn).To(Equal(packetConn))
			Expect(version).To(Equal(config.Versions[0]))
			Expect(conf.Versions).To(Equal(config.Versions))
		})

		It("creates a new connections after version negotiation", func() {
			var counter int
			newClientConnection = func(
				_ sendConn,
				runner connRunner,
				_ protocol.ConnectionID,
				connID protocol.ConnectionID,
				_ ConnectionIDGenerator,
				configP *Config,
				_ *tls.Config,
				pn protocol.PacketNumber,
				_ bool,
				hasNegotiatedVersion bool,
				_ logging.ConnectionTracer,
				_ uint64,
				_ utils.Logger,
				versionP protocol.VersionNumber,
			) quicConn {
				conn := NewMockQUICConn(mockCtrl)
				conn.EXPECT().HandshakeComplete().Return(make(chan struct{}))
				if counter == 0 {
					Expect(pn).To(BeZero())
					Expect(hasNegotiatedVersion).To(BeFalse())
					conn.EXPECT().run().DoAndReturn(func() error {
						runner.Remove(connID)
						return &errCloseForRecreating{
							nextPacketNumber: 109,
							nextVersion:      789,
						}
					})
				} else {
					Expect(pn).To(Equal(protocol.PacketNumber(109)))
					Expect(hasNegotiatedVersion).To(BeTrue())
					conn.EXPECT().run()
					conn.EXPECT().destroy(gomock.Any())
				}
				counter++
				return conn
			}

			config := &Config{Tracer: config.Tracer, Versions: []protocol.VersionNumber{protocol.Version1}}
			tracer.EXPECT().StartedConnection(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any())
			_, err := DialAddr(context.Background(), "localhost:7890", tlsConf, config)
			Expect(err).ToNot(HaveOccurred())
			Expect(counter).To(Equal(2))
		})
	})
})
