package self_test

import (
	"bufio"
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	mrand "math/rand"
	"os"
	"runtime/pprof"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ed25519"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/internal/utils"
	"github.com/quic-go/quic-go/internal/wire"
	"github.com/quic-go/quic-go/logging"
	"github.com/quic-go/quic-go/qlog"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

const alpn = "quic-go integration tests"

const (
	dataLen     = 500 * 1024       // 500 KB
	dataLenLong = 50 * 1024 * 1024 // 50 MB
)

var (
	// PRData contains dataLen bytes of pseudo-random data.
	PRData = GeneratePRData(dataLen)
	// PRDataLong contains dataLenLong bytes of pseudo-random data.
	PRDataLong = GeneratePRData(dataLenLong)
)

// See https://en.wikipedia.org/wiki/Lehmer_random_number_generator
func GeneratePRData(l int) []byte {
	res := make([]byte, l)
	seed := uint64(1)
	for i := 0; i < l; i++ {
		seed = seed * 48271 % 2147483647
		res[i] = byte(seed)
	}
	return res
}

const logBufSize = 100 * 1 << 20 // initial size of the log buffer: 100 MB

type syncedBuffer struct {
	mutex sync.Mutex

	*bytes.Buffer
}

func (b *syncedBuffer) Write(p []byte) (int, error) {
	b.mutex.Lock()
	n, err := b.Buffer.Write(p)
	b.mutex.Unlock()
	return n, err
}

func (b *syncedBuffer) Bytes() []byte {
	b.mutex.Lock()
	p := b.Buffer.Bytes()
	b.mutex.Unlock()
	return p
}

func (b *syncedBuffer) Reset() {
	b.mutex.Lock()
	b.Buffer.Reset()
	b.mutex.Unlock()
}

var (
	logFileName string // the log file set in the ginkgo flags
	logBufOnce  sync.Once
	logBuf      *syncedBuffer
	enableQlog  bool

	tlsConfig          *tls.Config
	tlsConfigLongChain *tls.Config
	tlsClientConfig    *tls.Config
	quicConfigTracer   logging.Tracer
)

// read the logfile command line flag
// to set call ginkgo -- -logfile=log.txt
func init() {
	flag.StringVar(&logFileName, "logfile", "", "log file")
	flag.BoolVar(&enableQlog, "qlog", false, "enable qlog")
}

var _ = BeforeSuite(func() {
	mrand.Seed(GinkgoRandomSeed())

	ca, caPrivateKey, err := generateCA()
	if err != nil {
		panic(err)
	}
	leafCert, leafPrivateKey, err := generateLeafCert(ca, caPrivateKey)
	if err != nil {
		panic(err)
	}
	tlsConfig = &tls.Config{
		Certificates: []tls.Certificate{{
			Certificate: [][]byte{leafCert.Raw},
			PrivateKey:  leafPrivateKey,
		}},
		NextProtos: []string{alpn},
	}
	tlsConfLongChain, err := generateTLSConfigWithLongCertChain(ca, caPrivateKey)
	if err != nil {
		panic(err)
	}
	tlsConfigLongChain = tlsConfLongChain

	root := x509.NewCertPool()
	root.AddCert(ca)
	tlsClientConfig = &tls.Config{
		RootCAs:    root,
		NextProtos: []string{alpn},
	}

	if enableQlog {
		quicConfigTracer = qlog.NewTracer(func(p logging.Perspective, connectionID []byte) io.WriteCloser {
			role := "server"
			if p == logging.PerspectiveClient {
				role = "client"
			}
			filename := fmt.Sprintf("log_%x_%s.qlog", connectionID, role)
			fmt.Fprintf(GinkgoWriter, "Creating %s.\n", filename)
			f, err := os.Create(filename)
			Expect(err).ToNot(HaveOccurred())
			bw := bufio.NewWriter(f)
			return utils.NewBufferedWriteCloser(bw, f)
		})
	}
})

func generateCA() (*x509.Certificate, crypto.PrivateKey, error) {
	certTempl := &x509.Certificate{
		SerialNumber:          big.NewInt(2019),
		Subject:               pkix.Name{},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	caBytes, err := x509.CreateCertificate(rand.Reader, certTempl, certTempl, pub, priv)
	if err != nil {
		return nil, nil, err
	}
	ca, err := x509.ParseCertificate(caBytes)
	if err != nil {
		return nil, nil, err
	}
	return ca, priv, nil
}

func generateLeafCert(ca *x509.Certificate, caPriv crypto.PrivateKey) (*x509.Certificate, crypto.PrivateKey, error) {
	certTempl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		DNSNames:     []string{"localhost"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(24 * time.Hour),
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	certBytes, err := x509.CreateCertificate(rand.Reader, certTempl, ca, pub, caPriv)
	if err != nil {
		return nil, nil, err
	}
	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return nil, nil, err
	}
	return cert, priv, nil
}

// getTLSConfigWithLongCertChain generates a tls.Config that uses a long certificate chain.
// The Root CA used is the same as for the config returned from getTLSConfig().
func generateTLSConfigWithLongCertChain(ca *x509.Certificate, caPrivateKey crypto.PrivateKey) (*tls.Config, error) {
	const chainLen = 7
	certTempl := &x509.Certificate{
		SerialNumber:          big.NewInt(2019),
		Subject:               pkix.Name{},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	lastCA := ca
	lastCAPrivKey := caPrivateKey
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	certs := make([]*x509.Certificate, chainLen)
	for i := 0; i < chainLen; i++ {
		caBytes, err := x509.CreateCertificate(rand.Reader, certTempl, lastCA, &privKey.PublicKey, lastCAPrivKey)
		if err != nil {
			return nil, err
		}
		ca, err := x509.ParseCertificate(caBytes)
		if err != nil {
			return nil, err
		}
		certs[i] = ca
		lastCA = ca
		lastCAPrivKey = privKey
	}
	leafCert, leafPrivateKey, err := generateLeafCert(lastCA, lastCAPrivKey)
	if err != nil {
		return nil, err
	}

	rawCerts := make([][]byte, chainLen+1)
	for i, cert := range certs {
		rawCerts[chainLen-i] = cert.Raw
	}
	rawCerts[0] = leafCert.Raw

	return &tls.Config{
		Certificates: []tls.Certificate{{
			Certificate: rawCerts,
			PrivateKey:  leafPrivateKey,
		}},
		NextProtos: []string{alpn},
	}, nil
}

func getTLSConfig() *tls.Config {
	return tlsConfig.Clone()
}

func getTLSConfigWithLongCertChain() *tls.Config {
	return tlsConfigLongChain.Clone()
}

func getTLSClientConfig() *tls.Config {
	return tlsClientConfig.Clone()
}

func getQuicConfig(conf *quic.Config) *quic.Config {
	if conf == nil {
		conf = &quic.Config{}
	} else {
		conf = conf.Clone()
	}
	if conf.Tracer == nil {
		conf.Tracer = quicConfigTracer
	} else if quicConfigTracer != nil {
		conf.Tracer = logging.NewMultiplexedTracer(quicConfigTracer, conf.Tracer)
	}
	return conf
}

var _ = BeforeEach(func() {
	log.SetFlags(log.Ldate | log.Ltime | log.Lmicroseconds)

	if debugLog() {
		logBufOnce.Do(func() {
			logBuf = &syncedBuffer{Buffer: bytes.NewBuffer(make([]byte, 0, logBufSize))}
		})
		utils.DefaultLogger.SetLogLevel(utils.LogLevelDebug)
		log.SetOutput(logBuf)
	}
})

func areHandshakesRunning() bool {
	var b bytes.Buffer
	pprof.Lookup("goroutine").WriteTo(&b, 1)
	return strings.Contains(b.String(), "RunHandshake")
}

var _ = AfterEach(func() {
	Expect(areHandshakesRunning()).To(BeFalse())
	if debugLog() {
		logFile, err := os.Create(logFileName)
		Expect(err).ToNot(HaveOccurred())
		logFile.Write(logBuf.Bytes())
		logFile.Close()
		logBuf.Reset()
	}
})

// Debug says if this test is being logged
func debugLog() bool {
	return len(logFileName) > 0
}

func scaleDuration(d time.Duration) time.Duration {
	scaleFactor := 1
	if f, err := strconv.Atoi(os.Getenv("TIMESCALE_FACTOR")); err == nil { // parsing "" errors, so this works fine if the env is not set
		scaleFactor = f
	}
	Expect(scaleFactor).ToNot(BeZero())
	return time.Duration(scaleFactor) * d
}

type tracer struct {
	logging.NullTracer
	createNewConnTracer func() logging.ConnectionTracer
}

var _ logging.Tracer = &tracer{}

func newTracer(c func() logging.ConnectionTracer) logging.Tracer {
	return &tracer{createNewConnTracer: c}
}

func (t *tracer) TracerForConnection(context.Context, logging.Perspective, logging.ConnectionID) logging.ConnectionTracer {
	return t.createNewConnTracer()
}

type packet struct {
	time   time.Time
	hdr    *logging.ExtendedHeader
	frames []logging.Frame
}

type shortHeaderPacket struct {
	time   time.Time
	hdr    *logging.ShortHeader
	frames []logging.Frame
}

type packetTracer struct {
	logging.NullConnectionTracer
	closed                     chan struct{}
	sentShortHdr, rcvdShortHdr []shortHeaderPacket
	rcvdLongHdr                []packet
}

func newPacketTracer() *packetTracer {
	return &packetTracer{closed: make(chan struct{})}
}

func (t *packetTracer) ReceivedLongHeaderPacket(hdr *logging.ExtendedHeader, _ logging.ByteCount, frames []logging.Frame) {
	t.rcvdLongHdr = append(t.rcvdLongHdr, packet{time: time.Now(), hdr: hdr, frames: frames})
}

func (t *packetTracer) ReceivedShortHeaderPacket(hdr *logging.ShortHeader, _ logging.ByteCount, frames []logging.Frame) {
	t.rcvdShortHdr = append(t.rcvdShortHdr, shortHeaderPacket{time: time.Now(), hdr: hdr, frames: frames})
}

func (t *packetTracer) SentShortHeaderPacket(hdr *logging.ShortHeader, _ logging.ByteCount, ack *wire.AckFrame, frames []logging.Frame) {
	if ack != nil {
		frames = append(frames, ack)
	}
	t.sentShortHdr = append(t.sentShortHdr, shortHeaderPacket{time: time.Now(), hdr: hdr, frames: frames})
}

func (t *packetTracer) Close() { close(t.closed) }

func (t *packetTracer) getSentShortHeaderPackets() []shortHeaderPacket {
	<-t.closed
	return t.sentShortHdr
}

func (t *packetTracer) getRcvdLongHeaderPackets() []packet {
	<-t.closed
	return t.rcvdLongHdr
}

func (t *packetTracer) getRcvdShortHeaderPackets() []shortHeaderPacket {
	<-t.closed
	return t.rcvdShortHdr
}

func TestSelf(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Self integration tests")
}
