package versionnegotiation

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"net"
	"os"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/integrationtests/tools"
	"github.com/quic-go/quic-go/qlogwriter"
	"github.com/quic-go/quic-go/testutils/simnet"

	"github.com/stretchr/testify/require"
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

func newSimnetLink(t *testing.T, rtt time.Duration) (client, server *simnet.SimConn, close func(t *testing.T)) {
	t.Helper()

	n := &simnet.Simnet{Router: &simnet.PerfectRouter{}}
	settings := simnet.NodeBiDiLinkSettings{Latency: rtt / 2}
	clientPacketConn := n.NewEndpoint(&net.UDPAddr{IP: net.ParseIP("1.0.0.1"), Port: 9001}, settings)
	serverPacketConn := n.NewEndpoint(&net.UDPAddr{IP: net.ParseIP("1.0.0.2"), Port: 9002}, settings)

	return clientPacketConn, serverPacketConn, func(t *testing.T) {
		require.NoError(t, clientPacketConn.Close())
		require.NoError(t, serverPacketConn.Close())
		require.NoError(t, n.Close())
	}
}

type multiplexedRecorder struct {
	Recorders []qlogwriter.Recorder
}

var _ qlogwriter.Recorder = &multiplexedRecorder{}

func (r *multiplexedRecorder) Close() error {
	for _, recorder := range r.Recorders {
		recorder.Close()
	}
	return nil
}

func (r *multiplexedRecorder) RecordEvent(ev qlogwriter.Event) {
	for _, recorder := range r.Recorders {
		recorder.RecordEvent(ev)
	}
}

type multiplexedTrace struct {
	Traces []qlogwriter.Trace
}

var _ qlogwriter.Trace = &multiplexedTrace{}

func (t *multiplexedTrace) AddProducer() qlogwriter.Recorder {
	recorders := make([]qlogwriter.Recorder, 0, len(t.Traces))
	for _, tr := range t.Traces {
		recorders = append(recorders, tr.AddProducer())
	}
	return &multiplexedRecorder{Recorders: recorders}
}

func maybeAddQLOGTracer(c *quic.Config) *quic.Config {
	if c == nil {
		c = &quic.Config{}
	}
	if !enableQlog {
		return c
	}
	qlogger := tools.NewQlogConnectionTracer(os.Stdout)
	if c.Tracer == nil {
		c.Tracer = qlogger
	} else if qlogger != nil {
		origTracer := c.Tracer
		c.Tracer = func(ctx context.Context, p bool, connID quic.ConnectionID) qlogwriter.Trace {
			var traces []qlogwriter.Trace
			if origTracer != nil {
				traces = append(traces, origTracer(ctx, p, connID))
			}
			if qlogger != nil {
				traces = append(traces, qlogger(ctx, p, connID))
			}
			return &multiplexedTrace{Traces: traces}
		}
	}
	return c
}
