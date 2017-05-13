package handshake

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net"
	"time"

	"github.com/lucas-clemente/quic-go/crypto"
	"github.com/lucas-clemente/quic-go/protocol"
	"github.com/lucas-clemente/quic-go/qerr"
	"github.com/lucas-clemente/quic-go/utils"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

type mockKEX struct {
	ephermal       bool
	sharedKeyError error
}

func (m *mockKEX) PublicKey() []byte {
	if m.ephermal {
		return []byte("ephermal pub")
	}
	return []byte("initial public")
}

func (m *mockKEX) CalculateSharedKey(otherPublic []byte) ([]byte, error) {
	if m.sharedKeyError != nil {
		return nil, m.sharedKeyError
	}
	if m.ephermal {
		return []byte("shared ephermal"), nil
	}
	return []byte("shared key"), nil
}

type mockSigner struct {
	gotCHLO bool
}

func (s *mockSigner) SignServerProof(sni string, chlo []byte, serverConfigData []byte) ([]byte, error) {
	if len(chlo) > 0 {
		s.gotCHLO = true
	}
	return []byte("proof"), nil
}
func (*mockSigner) GetCertsCompressed(sni string, common, cached []byte) ([]byte, error) {
	return []byte("certcompressed"), nil
}
func (*mockSigner) GetLeafCert(sni string) ([]byte, error) {
	return []byte("certuncompressed"), nil
}

type mockAEAD struct {
	forwardSecure bool
	sharedSecret  []byte
}

func (m *mockAEAD) Seal(dst, src []byte, packetNumber protocol.PacketNumber, associatedData []byte) []byte {
	if cap(dst) < len(src)+12 {
		dst = make([]byte, len(src)+12)
	}
	dst = dst[:len(src)+12]
	copy(dst, src)
	if !m.forwardSecure {
		copy(dst[len(src):], []byte("  normal sec"))
	} else {
		copy(dst[len(src):], []byte(" forward sec"))
	}
	return dst
}

func (m *mockAEAD) Open(dst, src []byte, packetNumber protocol.PacketNumber, associatedData []byte) ([]byte, error) {
	if m.forwardSecure && string(src) == "forward secure encrypted" {
		return []byte("decrypted"), nil
	} else if !m.forwardSecure && string(src) == "encrypted" {
		return []byte("decrypted"), nil
	}
	return nil, errors.New("authentication failed")
}

var expectedInitialNonceLen int
var expectedFSNonceLen int

func mockKeyDerivation(forwardSecure bool, sharedSecret, nonces []byte, connID protocol.ConnectionID, chlo []byte, scfg []byte, cert []byte, divNonce []byte, pers protocol.Perspective) (crypto.AEAD, error) {
	if forwardSecure {
		Expect(nonces).To(HaveLen(expectedFSNonceLen))
	} else {
		Expect(nonces).To(HaveLen(expectedInitialNonceLen))
	}
	return &mockAEAD{forwardSecure: forwardSecure, sharedSecret: sharedSecret}, nil
}

type mockStream struct {
	unblockRead chan struct{} // close this chan to unblock Read
	dataToRead  bytes.Buffer
	dataWritten bytes.Buffer
}

func newMockStream() *mockStream {
	return &mockStream{unblockRead: make(chan struct{})}
}

func (s *mockStream) Read(p []byte) (int, error) {
	n, _ := s.dataToRead.Read(p)
	if n == 0 { // block if there's no data
		<-s.unblockRead
	}
	return n, nil // never return an EOF
}

func (s *mockStream) ReadByte() (byte, error) {
	return s.dataToRead.ReadByte()
}

func (s *mockStream) Write(p []byte) (int, error) {
	return s.dataWritten.Write(p)
}

func (s *mockStream) Close() error                       { panic("not implemented") }
func (s *mockStream) Reset(error)                        { panic("not implemented") }
func (mockStream) CloseRemote(offset protocol.ByteCount) { panic("not implemented") }
func (s mockStream) StreamID() protocol.StreamID         { panic("not implemented") }

type mockStkSource struct {
	verifyErr error
	stkTime   time.Time
}

var _ crypto.StkSource = &mockStkSource{}

func (mockStkSource) NewToken(sourceAddr []byte) ([]byte, error) {
	return append([]byte("token "), sourceAddr...), nil
}

func (s mockStkSource) VerifyToken(sourceAddr []byte, token []byte) (time.Time, error) {
	if s.verifyErr != nil {
		return time.Time{}, s.verifyErr
	}
	split := bytes.Split(token, []byte(" "))
	if len(split) != 2 {
		return time.Time{}, errors.New("stk required")
	}
	if !bytes.Equal(split[0], []byte("token")) {
		return time.Time{}, errors.New("no prefix match")
	}
	if !bytes.Equal(split[1], sourceAddr) {
		return time.Time{}, errors.New("ip wrong")
	}
	if !s.stkTime.IsZero() {
		return s.stkTime, nil
	}
	return time.Now(), nil
}

var _ = Describe("Server Crypto Setup", func() {
	var (
		kex               *mockKEX
		signer            *mockSigner
		scfg              *ServerConfig
		cs                *cryptoSetupServer
		stream            *mockStream
		cpm               ConnectionParametersManager
		aeadChanged       chan protocol.EncryptionLevel
		nonce32           []byte
		versionTag        []byte
		validSTK          []byte
		aead              []byte
		kexs              []byte
		version           protocol.VersionNumber
		supportedVersions []protocol.VersionNumber
	)

	BeforeEach(func() {
		var err error
		remoteAddr := &net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 1234}
		validSTK, err = mockStkSource{}.NewToken(remoteAddr.IP)
		Expect(err).NotTo(HaveOccurred())
		expectedInitialNonceLen = 32
		expectedFSNonceLen = 64
		aeadChanged = make(chan protocol.EncryptionLevel, 2)
		stream = newMockStream()
		kex = &mockKEX{}
		signer = &mockSigner{}
		scfg, err = NewServerConfig(kex, signer)
		nonce32 = make([]byte, 32)
		aead = []byte("AESG")
		kexs = []byte("C255")
		copy(nonce32[4:12], scfg.obit) // set the OBIT value at the right position
		versionTag = make([]byte, 4)
		binary.LittleEndian.PutUint32(versionTag, protocol.VersionNumberToTag(protocol.VersionWhatever))
		Expect(err).NotTo(HaveOccurred())
		version = protocol.SupportedVersions[len(protocol.SupportedVersions)-1]
		supportedVersions = []protocol.VersionNumber{version, 98, 99}
		cpm = NewConnectionParamatersManager(protocol.PerspectiveServer, protocol.VersionWhatever)
		csInt, err := NewCryptoSetup(
			protocol.ConnectionID(42),
			remoteAddr,
			version,
			scfg,
			stream,
			cpm,
			supportedVersions,
			aeadChanged,
		)
		Expect(err).NotTo(HaveOccurred())
		cs = csInt.(*cryptoSetupServer)
		cs.stkGenerator.stkSource = &mockStkSource{}
		cs.keyDerivation = mockKeyDerivation
		cs.keyExchange = func() crypto.KeyExchange { return &mockKEX{ephermal: true} }
	})

	AfterEach(func() {
		close(stream.unblockRead)
	})

	Context("diversification nonce", func() {
		BeforeEach(func() {
			cs.version = protocol.Version35
			cs.secureAEAD = &mockAEAD{}
			cs.receivedForwardSecurePacket = false

			Expect(cs.DiversificationNonce()).To(BeEmpty())
			// Div nonce is created after CHLO
			cs.handleCHLO("", nil, map[Tag][]byte{TagNONC: nonce32})
		})

		It("returns diversification nonces", func() {
			Expect(cs.DiversificationNonce()).To(HaveLen(32))
		})
	})

	Context("source address token", func() {
		It("uses the IP address when the remote address is a UDP address", func() {
			remoteAddr := &net.UDPAddr{IP: net.IPv4(1, 3, 3, 7), Port: 1337}
			cs, err := NewCryptoSetup(
				protocol.ConnectionID(42),
				remoteAddr,
				protocol.VersionWhatever,
				scfg,
				stream,
				cpm,
				supportedVersions,
				aeadChanged,
			)
			Expect(err).ToNot(HaveOccurred())
			Expect(cs.(*cryptoSetupServer).sourceAddr).To(BeEquivalentTo(remoteAddr.IP))
		})

		It("works with remote address that are not UDP", func() {
			remoteAddr := &net.TCPAddr{IP: net.IPv4(1, 3, 3, 7), Port: 1337}
			cs, err := NewCryptoSetup(
				protocol.ConnectionID(42),
				remoteAddr,
				protocol.VersionWhatever,
				scfg,
				stream,
				cpm,
				supportedVersions,
				aeadChanged,
			)
			Expect(err).ToNot(HaveOccurred())
			Expect(cs.(*cryptoSetupServer).sourceAddr).To(BeEquivalentTo("1.3.3.7:1337"))
		})
	})

	Context("when responding to client messages", func() {
		var cert []byte
		var xlct []byte
		var fullCHLO map[Tag][]byte

		BeforeEach(func() {
			xlct = make([]byte, 8)
			var err error
			cert, err = cs.scfg.certChain.GetLeafCert("")
			Expect(err).ToNot(HaveOccurred())
			binary.LittleEndian.PutUint64(xlct, crypto.HashCert(cert))
			fullCHLO = map[Tag][]byte{
				TagSCID: scfg.ID,
				TagSNI:  []byte("quic.clemente.io"),
				TagNONC: nonce32,
				TagSTK:  validSTK,
				TagXLCT: xlct,
				TagAEAD: aead,
				TagKEXS: kexs,
				TagPUBS: bytes.Repeat([]byte{'e'}, 31),
				TagVER:  versionTag,
			}
		})

		It("doesn't support Chrome's head-of-line blocking experiment", func() {
			HandshakeMessage{
				Tag: TagCHLO,
				Data: map[Tag][]byte{
					TagFHL2: []byte("foobar"),
				},
			}.Write(&stream.dataToRead)
			err := cs.HandleCryptoStream()
			Expect(err).To(MatchError(ErrHOLExperiment))
		})

		It("generates REJ messages", func() {
			response, err := cs.handleInchoateCHLO("", bytes.Repeat([]byte{'a'}, protocol.ClientHelloMinimumSize), nil)
			Expect(err).ToNot(HaveOccurred())
			Expect(response).To(HavePrefix("REJ"))
			Expect(response).To(ContainSubstring("initial public"))
			Expect(signer.gotCHLO).To(BeFalse())
		})

		It("REJ messages don't include cert or proof without STK", func() {
			response, err := cs.handleInchoateCHLO("", bytes.Repeat([]byte{'a'}, protocol.ClientHelloMinimumSize), nil)
			Expect(err).ToNot(HaveOccurred())
			Expect(response).To(HavePrefix("REJ"))
			Expect(response).ToNot(ContainSubstring("certcompressed"))
			Expect(response).ToNot(ContainSubstring("proof"))
			Expect(signer.gotCHLO).To(BeFalse())
		})

		It("REJ messages include cert and proof with valid STK", func() {
			response, err := cs.handleInchoateCHLO("", bytes.Repeat([]byte{'a'}, protocol.ClientHelloMinimumSize), map[Tag][]byte{
				TagSTK: validSTK,
				TagSNI: []byte("foo"),
			})
			Expect(err).ToNot(HaveOccurred())
			Expect(response).To(HavePrefix("REJ"))
			Expect(response).To(ContainSubstring("certcompressed"))
			Expect(response).To(ContainSubstring("proof"))
			Expect(signer.gotCHLO).To(BeTrue())
		})

		It("generates SHLO messages", func() {
			response, err := cs.handleCHLO("", []byte("chlo-data"), map[Tag][]byte{
				TagPUBS: []byte("pubs-c"),
				TagNONC: nonce32,
				TagAEAD: aead,
				TagKEXS: kexs,
			})
			Expect(err).ToNot(HaveOccurred())
			Expect(response).To(HavePrefix("SHLO"))
			Expect(response).To(ContainSubstring("ephermal pub"))
			Expect(response).To(ContainSubstring("SNO\x00"))
			for _, v := range supportedVersions {
				b := &bytes.Buffer{}
				utils.WriteUint32(b, protocol.VersionNumberToTag(v))
				Expect(response).To(ContainSubstring(string(b.Bytes())))
			}
			Expect(cs.secureAEAD).ToNot(BeNil())
			Expect(cs.secureAEAD.(*mockAEAD).forwardSecure).To(BeFalse())
			Expect(cs.secureAEAD.(*mockAEAD).sharedSecret).To(Equal([]byte("shared key")))
			Expect(cs.forwardSecureAEAD).ToNot(BeNil())
			Expect(cs.forwardSecureAEAD.(*mockAEAD).sharedSecret).To(Equal([]byte("shared ephermal")))
			Expect(cs.forwardSecureAEAD.(*mockAEAD).forwardSecure).To(BeTrue())
		})

		It("handles long handshake", func() {
			HandshakeMessage{
				Tag: TagCHLO,
				Data: map[Tag][]byte{
					TagSNI: []byte("quic.clemente.io"),
					TagSTK: validSTK,
					TagPAD: bytes.Repeat([]byte{'a'}, protocol.ClientHelloMinimumSize),
					TagVER: versionTag,
				},
			}.Write(&stream.dataToRead)
			HandshakeMessage{Tag: TagCHLO, Data: fullCHLO}.Write(&stream.dataToRead)
			err := cs.HandleCryptoStream()
			Expect(err).NotTo(HaveOccurred())
			Expect(stream.dataWritten.Bytes()).To(HavePrefix("REJ"))
			Expect(aeadChanged).To(Receive(Equal(protocol.EncryptionSecure)))
			Expect(stream.dataWritten.Bytes()).To(ContainSubstring("SHLO"))
			Expect(aeadChanged).To(Receive(Equal(protocol.EncryptionForwardSecure)))
			Expect(aeadChanged).ToNot(Receive())
			Expect(aeadChanged).ToNot(BeClosed())
		})

		It("rejects client nonces that have the wrong length", func() {
			fullCHLO[TagNONC] = []byte("too short client nonce")
			HandshakeMessage{Tag: TagCHLO, Data: fullCHLO}.Write(&stream.dataToRead)
			err := cs.HandleCryptoStream()
			Expect(err).To(MatchError(qerr.Error(qerr.InvalidCryptoMessageParameter, "invalid client nonce length")))
		})

		It("rejects client nonces that have the wrong OBIT value", func() {
			fullCHLO[TagNONC] = make([]byte, 32) // the OBIT value is nonce[4:12] and here just initialized to 0
			HandshakeMessage{Tag: TagCHLO, Data: fullCHLO}.Write(&stream.dataToRead)
			err := cs.HandleCryptoStream()
			Expect(err).To(MatchError(qerr.Error(qerr.InvalidCryptoMessageParameter, "OBIT not matching")))
		})

		It("errors if it can't calculate a shared key", func() {
			testErr := errors.New("test error")
			kex.sharedKeyError = testErr
			HandshakeMessage{Tag: TagCHLO, Data: fullCHLO}.Write(&stream.dataToRead)
			err := cs.HandleCryptoStream()
			Expect(err).To(MatchError(testErr))
		})

		It("handles 0-RTT handshake", func() {
			HandshakeMessage{Tag: TagCHLO, Data: fullCHLO}.Write(&stream.dataToRead)
			err := cs.HandleCryptoStream()
			Expect(err).NotTo(HaveOccurred())
			Expect(stream.dataWritten.Bytes()).To(HavePrefix("SHLO"))
			Expect(stream.dataWritten.Bytes()).ToNot(ContainSubstring("REJ"))
			Expect(aeadChanged).To(Receive(Equal(protocol.EncryptionSecure)))
			Expect(aeadChanged).To(Receive(Equal(protocol.EncryptionForwardSecure)))
		})

		It("recognizes inchoate CHLOs missing SCID", func() {
			delete(fullCHLO, TagSCID)
			Expect(cs.isInchoateCHLO(fullCHLO, cert)).To(BeTrue())
		})

		It("recognizes inchoate CHLOs missing PUBS", func() {
			delete(fullCHLO, TagPUBS)
			Expect(cs.isInchoateCHLO(fullCHLO, cert)).To(BeTrue())
		})

		It("recognizes inchoate CHLOs with missing XLCT", func() {
			delete(fullCHLO, TagXLCT)
			Expect(cs.isInchoateCHLO(fullCHLO, cert)).To(BeTrue())
		})

		It("recognizes inchoate CHLOs with wrong length XLCT", func() {
			fullCHLO[TagXLCT] = bytes.Repeat([]byte{'f'}, 7) // should be 8 bytes
			Expect(cs.isInchoateCHLO(fullCHLO, cert)).To(BeTrue())
		})

		It("recognizes inchoate CHLOs with wrong XLCT", func() {
			fullCHLO[TagXLCT] = bytes.Repeat([]byte{'f'}, 8)
			Expect(cs.isInchoateCHLO(fullCHLO, cert)).To(BeTrue())
		})

		It("recognizes inchoate CHLOs with an invalid STK", func() {
			testErr := errors.New("STK invalid")
			cs.stkGenerator.stkSource.(*mockStkSource).verifyErr = testErr
			Expect(cs.isInchoateCHLO(fullCHLO, cert)).To(BeTrue())
		})

		It("REJ messages that have an expired STK", func() {
			cs.stkGenerator.stkSource.(*mockStkSource).stkTime = time.Now().Add(-protocol.STKExpiryTime).Add(-time.Second)
			Expect(cs.isInchoateCHLO(fullCHLO, cert)).To(BeTrue())
		})

		It("recognizes proper CHLOs", func() {
			Expect(cs.isInchoateCHLO(fullCHLO, cert)).To(BeFalse())
		})

		It("errors on too short inchoate CHLOs", func() {
			_, err := cs.handleInchoateCHLO("", bytes.Repeat([]byte{'a'}, protocol.ClientHelloMinimumSize-1), nil)
			Expect(err).To(MatchError("CryptoInvalidValueLength: CHLO too small"))
		})

		It("rejects CHLOs without the version tag", func() {
			HandshakeMessage{
				Tag: TagCHLO,
				Data: map[Tag][]byte{
					TagSCID: scfg.ID,
					TagSNI:  []byte("quic.clemente.io"),
				},
			}.Write(&stream.dataToRead)
			err := cs.HandleCryptoStream()
			Expect(err).To(MatchError(qerr.Error(qerr.InvalidCryptoMessageParameter, "client hello missing version tag")))
		})

		It("rejects CHLOs with a version tag that has the wrong length", func() {
			fullCHLO[TagVER] = []byte{0x13, 0x37} // should be 4 bytes
			HandshakeMessage{Tag: TagCHLO, Data: fullCHLO}.Write(&stream.dataToRead)
			err := cs.HandleCryptoStream()
			Expect(err).To(MatchError(qerr.Error(qerr.InvalidCryptoMessageParameter, "incorrect version tag")))
		})

		It("detects version downgrade attacks", func() {
			highestSupportedVersion := supportedVersions[len(protocol.SupportedVersions)-1]
			lowestSupportedVersion := supportedVersions[0]
			Expect(highestSupportedVersion).ToNot(Equal(lowestSupportedVersion))
			cs.version = highestSupportedVersion
			b := make([]byte, 4)
			binary.LittleEndian.PutUint32(b, protocol.VersionNumberToTag(lowestSupportedVersion))
			fullCHLO[TagVER] = b
			HandshakeMessage{Tag: TagCHLO, Data: fullCHLO}.Write(&stream.dataToRead)
			err := cs.HandleCryptoStream()
			Expect(err).To(MatchError(qerr.Error(qerr.VersionNegotiationMismatch, "Downgrade attack detected")))
		})

		It("accepts a non-matching version tag in the CHLO, if it is an unsupported version", func() {
			supportedVersion := protocol.SupportedVersions[0]
			unsupportedVersion := supportedVersion + 1000
			Expect(protocol.IsSupportedVersion(supportedVersions, unsupportedVersion)).To(BeFalse())
			cs.version = supportedVersion
			b := make([]byte, 4)
			binary.LittleEndian.PutUint32(b, protocol.VersionNumberToTag(unsupportedVersion))
			fullCHLO[TagVER] = b
			HandshakeMessage{Tag: TagCHLO, Data: fullCHLO}.Write(&stream.dataToRead)
			err := cs.HandleCryptoStream()
			Expect(err).ToNot(HaveOccurred())
		})

		It("errors if the AEAD tag is missing", func() {
			delete(fullCHLO, TagAEAD)
			HandshakeMessage{Tag: TagCHLO, Data: fullCHLO}.Write(&stream.dataToRead)
			err := cs.HandleCryptoStream()
			Expect(err).To(MatchError(qerr.Error(qerr.CryptoNoSupport, "Unsupported AEAD or KEXS")))
		})

		It("errors if the AEAD tag has the wrong value", func() {
			fullCHLO[TagAEAD] = []byte("wrong")
			HandshakeMessage{Tag: TagCHLO, Data: fullCHLO}.Write(&stream.dataToRead)
			err := cs.HandleCryptoStream()
			Expect(err).To(MatchError(qerr.Error(qerr.CryptoNoSupport, "Unsupported AEAD or KEXS")))
		})

		It("errors if the KEXS tag is missing", func() {
			delete(fullCHLO, TagKEXS)
			HandshakeMessage{Tag: TagCHLO, Data: fullCHLO}.Write(&stream.dataToRead)
			err := cs.HandleCryptoStream()
			Expect(err).To(MatchError(qerr.Error(qerr.CryptoNoSupport, "Unsupported AEAD or KEXS")))
		})

		It("errors if the KEXS tag has the wrong value", func() {
			fullCHLO[TagKEXS] = []byte("wrong")
			HandshakeMessage{Tag: TagCHLO, Data: fullCHLO}.Write(&stream.dataToRead)
			err := cs.HandleCryptoStream()
			Expect(err).To(MatchError(qerr.Error(qerr.CryptoNoSupport, "Unsupported AEAD or KEXS")))
		})
	})

	It("errors without SNI", func() {
		HandshakeMessage{
			Tag: TagCHLO,
			Data: map[Tag][]byte{
				TagSTK: validSTK,
			},
		}.Write(&stream.dataToRead)
		err := cs.HandleCryptoStream()
		Expect(err).To(MatchError("CryptoMessageParameterNotFound: SNI required"))
	})

	It("errors with empty SNI", func() {
		HandshakeMessage{
			Tag: TagCHLO,
			Data: map[Tag][]byte{
				TagSTK: validSTK,
				TagSNI: nil,
			},
		}.Write(&stream.dataToRead)
		err := cs.HandleCryptoStream()
		Expect(err).To(MatchError("CryptoMessageParameterNotFound: SNI required"))
	})

	It("errors with invalid message", func() {
		stream.dataToRead.Write([]byte("invalid message"))
		err := cs.HandleCryptoStream()
		Expect(err).To(MatchError(qerr.HandshakeFailed))
	})

	It("errors with non-CHLO message", func() {
		HandshakeMessage{Tag: TagPAD, Data: nil}.Write(&stream.dataToRead)
		err := cs.HandleCryptoStream()
		Expect(err).To(MatchError(qerr.InvalidCryptoMessageType))
	})

	Context("escalating crypto", func() {
		var foobarServerFNVSigned []byte // a "foobar" sent by the server, FNV signed
		var foobarClientFNVSigned []byte // a "foobar" sent by the client, FNV signed

		BeforeEach(func() {
			nullAEADServer := crypto.NewNullAEAD(protocol.PerspectiveServer, version)
			foobarServerFNVSigned = nullAEADServer.Seal(nil, []byte("foobar"), 0, []byte{})
			nullAEADClient := crypto.NewNullAEAD(protocol.PerspectiveClient, version)
			foobarClientFNVSigned = nullAEADClient.Seal(nil, []byte("foobar"), 0, []byte{})
		})

		doCHLO := func() {
			_, err := cs.handleCHLO("", []byte("chlo-data"), map[Tag][]byte{
				TagPUBS: []byte("pubs-c"),
				TagNONC: nonce32,
				TagAEAD: aead,
				TagKEXS: kexs,
			})
			Expect(err).ToNot(HaveOccurred())
		}

		Context("null encryption", func() {
			It("is used initially", func() {
				enc, seal := cs.GetSealer()
				Expect(enc).To(Equal(protocol.EncryptionUnencrypted))
				d := seal(nil, []byte("foobar"), 0, []byte{})
				Expect(d).To(Equal(foobarServerFNVSigned))
			})

			It("is accepted initially", func() {
				d, enc, err := cs.Open(nil, foobarClientFNVSigned, 0, []byte{})
				Expect(err).ToNot(HaveOccurred())
				Expect(d).To(Equal([]byte("foobar")))
				Expect(enc).To(Equal(protocol.EncryptionUnencrypted))
			})

			It("errors if the has the wrong hash", func() {
				foobarClientFNVSigned[0]++
				_, enc, err := cs.Open(nil, foobarClientFNVSigned, 0, []byte{})
				Expect(err).To(MatchError("NullAEAD: failed to authenticate received data"))
				Expect(enc).To(Equal(protocol.EncryptionUnspecified))
			})

			It("is still accepted after CHLO", func() {
				doCHLO()
				Expect(cs.secureAEAD).ToNot(BeNil())
				_, enc, err := cs.Open(nil, foobarClientFNVSigned, 0, []byte{})
				Expect(err).ToNot(HaveOccurred())
				Expect(enc).To(Equal(protocol.EncryptionUnencrypted))
			})

			It("is not accepted after receiving secure packet", func() {
				doCHLO()
				Expect(cs.secureAEAD).ToNot(BeNil())
				d, enc, err := cs.Open(nil, []byte("encrypted"), 0, []byte{})
				Expect(enc).To(Equal(protocol.EncryptionSecure))
				Expect(err).ToNot(HaveOccurred())
				Expect(d).To(Equal([]byte("decrypted")))
				_, enc, err = cs.Open(nil, foobarClientFNVSigned, 0, []byte{})
				Expect(err).To(MatchError("authentication failed"))
				Expect(enc).To(Equal(protocol.EncryptionUnspecified))
			})

			It("is not used after CHLO", func() {
				doCHLO()
				enc, seal := cs.GetSealer()
				Expect(enc).ToNot(Equal(protocol.EncryptionUnencrypted))
				d := seal(nil, []byte("foobar"), 0, []byte{})
				Expect(d).ToNot(Equal(foobarServerFNVSigned))
			})
		})

		Context("initial encryption", func() {
			It("is used after CHLO", func() {
				doCHLO()
				enc, seal := cs.GetSealer()
				Expect(enc).To(Equal(protocol.EncryptionSecure))
				d := seal(nil, []byte("foobar"), 0, []byte{})
				Expect(d).To(Equal([]byte("foobar  normal sec")))
			})

			It("is accepted after CHLO", func() {
				doCHLO()
				d, enc, err := cs.Open(nil, []byte("encrypted"), 0, []byte{})
				Expect(enc).To(Equal(protocol.EncryptionSecure))
				Expect(err).ToNot(HaveOccurred())
				Expect(d).To(Equal([]byte("decrypted")))
			})

			It("is not accepted after receiving forward secure packet", func() {
				doCHLO()
				_, _, err := cs.Open(nil, []byte("forward secure encrypted"), 0, []byte{})
				Expect(err).ToNot(HaveOccurred())
				_, enc, err := cs.Open(nil, []byte("encrypted"), 0, []byte{})
				Expect(err).To(MatchError("authentication failed"))
				Expect(enc).To(Equal(protocol.EncryptionUnspecified))
			})
		})

		Context("forward secure encryption", func() {
			It("is used after sending out one packet with initial encryption", func() {
				doCHLO()
				enc, seal := cs.GetSealer()
				Expect(enc).To(Equal(protocol.EncryptionSecure))
				_ = seal(nil, []byte("SHLO"), 0, []byte{})
				enc, seal = cs.GetSealer()
				Expect(enc).To(Equal(protocol.EncryptionForwardSecure))
				d := seal(nil, []byte("foobar"), 0, []byte{})
				Expect(d).To(Equal([]byte("foobar forward sec")))
			})

			It("regards the handshake as complete once it receives a forward encrypted packet", func() {
				doCHLO()
				_, _, err := cs.Open(nil, []byte("forward secure encrypted"), 0, []byte{})
				Expect(err).ToNot(HaveOccurred())
				Expect(aeadChanged).To(Receive()) // consume the protocol.EncryptionSecure
				Expect(aeadChanged).To(Receive()) // consume the protocol.EncryptionForwardSecure
				Expect(aeadChanged).To(BeClosed())
			})
		})

		Context("forcing encryption levels", func() {
			It("forces null encryption", func() {
				seal, err := cs.GetSealerWithEncryptionLevel(protocol.EncryptionUnencrypted)
				Expect(err).ToNot(HaveOccurred())
				d := seal(nil, []byte("foobar"), 0, []byte{})
				Expect(d).To(Equal(foobarServerFNVSigned))
			})

			It("forces initial encryption", func() {
				doCHLO()
				seal, err := cs.GetSealerWithEncryptionLevel(protocol.EncryptionSecure)
				Expect(err).ToNot(HaveOccurred())
				d := seal(nil, []byte("foobar"), 0, []byte{})
				Expect(d).To(Equal([]byte("foobar  normal sec")))
			})

			It("errors of no AEAD for initial encryption is available", func() {
				seal, err := cs.GetSealerWithEncryptionLevel(protocol.EncryptionSecure)
				Expect(err).To(MatchError("CryptoSetupServer: no secureAEAD"))
				Expect(seal).To(BeNil())
			})

			It("forces forward-secure encryption", func() {
				doCHLO()
				seal, err := cs.GetSealerWithEncryptionLevel(protocol.EncryptionForwardSecure)
				Expect(err).ToNot(HaveOccurred())
				d := seal(nil, []byte("foobar"), 0, []byte{})
				Expect(d).To(Equal([]byte("foobar forward sec")))
			})

			It("errors of no AEAD for forward-secure encryption is available", func() {
				seal, err := cs.GetSealerWithEncryptionLevel(protocol.EncryptionForwardSecure)
				Expect(err).To(MatchError("CryptoSetupServer: no forwardSecureAEAD"))
				Expect(seal).To(BeNil())
			})

			It("errors if no encryption level is specified", func() {
				seal, err := cs.GetSealerWithEncryptionLevel(protocol.EncryptionUnspecified)
				Expect(err).To(MatchError("CryptoSetupServer: no encryption level specified"))
				Expect(seal).To(BeNil())
			})
		})
	})

	Context("STK verification and creation", func() {
		It("requires STK", func() {
			done, err := cs.handleMessage(bytes.Repeat([]byte{'a'}, protocol.ClientHelloMinimumSize), map[Tag][]byte{
				TagSNI: []byte("foo"),
				TagVER: versionTag,
			})
			Expect(done).To(BeFalse())
			Expect(err).To(BeNil())
			Expect(stream.dataWritten.Bytes()).To(ContainSubstring(string(validSTK)))
		})

		It("works with proper STK", func() {
			done, err := cs.handleMessage(bytes.Repeat([]byte{'a'}, protocol.ClientHelloMinimumSize), map[Tag][]byte{
				TagSTK: validSTK,
				TagSNI: []byte("foo"),
				TagVER: versionTag,
			})
			Expect(done).To(BeFalse())
			Expect(err).To(BeNil())
		})

		It("errors if IP does not match", func() {
			done, err := cs.handleMessage(bytes.Repeat([]byte{'a'}, protocol.ClientHelloMinimumSize), map[Tag][]byte{
				TagSNI: []byte("foo"),
				TagSTK: []byte("token \x04\x03\x03\x01"),
				TagVER: versionTag,
			})
			Expect(done).To(BeFalse())
			Expect(err).To(BeNil())
			Expect(stream.dataWritten.Bytes()).To(ContainSubstring(string(validSTK)))
		})
	})
})
