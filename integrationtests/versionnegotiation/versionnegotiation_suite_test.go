package versionnegotiation

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"testing"

	"github.com/quic-go/quic-go/integrationtests/tools"
	"github.com/quic-go/quic-go/logging"

	"github.com/quic-go/quic-go"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var (
	enableQlog      bool
	tlsConfig       *tls.Config
	tlsClientConfig *tls.Config
)

func init() {
	flag.BoolVar(&enableQlog, "qlog", false, "enable qlog")

	ca, caPrivateKey, err := tools.GenerateCA()
	if err != nil {
		panic(err)
	}
	leafCert, leafPrivateKey, err := tools.GenerateLeafCert(ca, caPrivateKey)
	if err != nil {
		panic(err)
	}
	tlsConfig = &tls.Config{
		Certificates: []tls.Certificate{{
			Certificate: [][]byte{leafCert.Raw},
			PrivateKey:  leafPrivateKey,
		}},
		NextProtos: []string{tools.ALPN},
	}

	root := x509.NewCertPool()
	root.AddCert(ca)
	tlsClientConfig = &tls.Config{
		ServerName: "localhost",
		RootCAs:    root,
		NextProtos: []string{tools.ALPN},
	}
}

func getTLSConfig() *tls.Config       { return tlsConfig }
func getTLSClientConfig() *tls.Config { return tlsClientConfig }

func TestQuicVersionNegotiation(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Version Negotiation Suite")
}

func maybeAddQlogTracer(c *quic.Config) *quic.Config {
	if c == nil {
		c = &quic.Config{}
	}
	if !enableQlog {
		return c
	}
	qlogger := tools.NewQlogger(GinkgoWriter)
	if c.Tracer == nil {
		c.Tracer = qlogger
	} else if qlogger != nil {
		c.Tracer = logging.NewMultiplexedTracer(qlogger, c.Tracer)
	}
	return c
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
