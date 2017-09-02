package handshake

import (
	gocrypto "crypto"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"time"

	"github.com/bifurcation/mint"
	"github.com/lucas-clemente/quic-go/crypto"
	"github.com/lucas-clemente/quic-go/internal/protocol"
)

func tlsToMintConfig(tlsConf *tls.Config, pers protocol.Perspective) (*mint.Config, error) {
	mconf := &mint.Config{
		NonBlocking: true,
		CipherSuites: []mint.CipherSuite{
			mint.TLS_AES_128_GCM_SHA256,
			mint.TLS_AES_256_GCM_SHA384,
		},
	}
	if tlsConf != nil {
		mconf.Certificates = make([]*mint.Certificate, len(tlsConf.Certificates))
		for i, certChain := range tlsConf.Certificates {
			mconf.Certificates[i] = &mint.Certificate{
				Chain:      make([]*x509.Certificate, len(certChain.Certificate)),
				PrivateKey: certChain.PrivateKey.(gocrypto.Signer),
			}
			for j, cert := range certChain.Certificate {
				c, err := x509.ParseCertificate(cert)
				if err != nil {
					return nil, err
				}
				mconf.Certificates[i].Chain[j] = c
			}
		}
	}
	if err := mconf.Init(pers == protocol.PerspectiveClient); err != nil {
		return nil, err
	}
	return mconf, nil
}

type mintState struct {
	conn *mint.Conn
}

var _ crypto.MintState = &mintState{}

func (ms *mintState) GetCipherSuite() mint.CipherSuiteParams {
	return ms.conn.State().CipherSuite
}

func (ms *mintState) ComputeExporter(label string, context []byte, keyLength int) ([]byte, error) {
	return ms.conn.ComputeExporter(label, context, keyLength)
}

// mint expects a net.Conn, but we're doing the handshake on a stream
// so we wrap a stream such that implements a net.Conn
type fakeConn struct {
	io.ReadWriter
}

var _ net.Conn = &fakeConn{}

func (c *fakeConn) Close() error                     { return nil }
func (c *fakeConn) LocalAddr() net.Addr              { return nil }
func (c *fakeConn) RemoteAddr() net.Addr             { return nil }
func (c *fakeConn) SetReadDeadline(time.Time) error  { return nil }
func (c *fakeConn) SetWriteDeadline(time.Time) error { return nil }
func (c *fakeConn) SetDeadline(time.Time) error      { return nil }
