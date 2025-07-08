package http3

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/quic-go/qpack"
	"github.com/quic-go/quic-go"

	"github.com/stretchr/testify/require"
)

// maxByteCount is the maximum value of a ByteCount
const maxByteCount = uint64(1<<62 - 1)

func newUDPConnLocalhost(t testing.TB) *net.UDPConn {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })
	return conn
}

func scaleDuration(t time.Duration) time.Duration {
	scaleFactor := 1
	if f, err := strconv.Atoi(os.Getenv("TIMESCALE_FACTOR")); err == nil { // parsing "" errors, so this works fine if the env is not set
		scaleFactor = f
	}
	if scaleFactor == 0 {
		panic("TIMESCALE_FACTOR is 0")
	}
	return time.Duration(scaleFactor) * t
}

var tlsConfig, tlsClientConfig *tls.Config

func init() {
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
		NextProtos: []string{NextProtoH3},
	}

	root := x509.NewCertPool()
	root.AddCert(ca)
	tlsClientConfig = &tls.Config{
		ServerName: "localhost",
		RootCAs:    root,
		NextProtos: []string{NextProtoH3},
	}
}

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
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
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

func getTLSConfig() *tls.Config       { return tlsConfig.Clone() }
func getTLSClientConfig() *tls.Config { return tlsClientConfig.Clone() }

func newConnPair(t *testing.T) (client, server *quic.Conn) {
	t.Helper()

	ln, err := quic.ListenEarly(
		newUDPConnLocalhost(t),
		getTLSConfig(),
		&quic.Config{
			InitialStreamReceiveWindow:     maxByteCount,
			InitialConnectionReceiveWindow: maxByteCount,
		},
	)
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	cl, err := quic.DialEarly(ctx, newUDPConnLocalhost(t), ln.Addr(), getTLSClientConfig(), &quic.Config{})
	require.NoError(t, err)
	t.Cleanup(func() { cl.CloseWithError(0, "") })

	conn, err := ln.Accept(ctx)
	require.NoError(t, err)
	t.Cleanup(func() { conn.CloseWithError(0, "") })
	select {
	case <-conn.HandshakeComplete():
	case <-ctx.Done():
		t.Fatal("timeout")
	}
	return cl, conn
}

func newConnPairWithDatagrams(t *testing.T) (client, server *quic.Conn) {
	t.Helper()

	ln, err := quic.ListenEarly(
		newUDPConnLocalhost(t),
		getTLSConfig(),
		&quic.Config{
			InitialStreamReceiveWindow:     maxByteCount,
			InitialConnectionReceiveWindow: maxByteCount,
			EnableDatagrams:                true,
		},
	)
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	cl, err := quic.DialEarly(ctx, newUDPConnLocalhost(t), ln.Addr(), getTLSClientConfig(), &quic.Config{EnableDatagrams: true})
	require.NoError(t, err)
	t.Cleanup(func() { cl.CloseWithError(0, "") })

	conn, err := ln.Accept(ctx)
	require.NoError(t, err)
	t.Cleanup(func() { conn.CloseWithError(0, "") })
	select {
	case <-conn.HandshakeComplete():
	case <-ctx.Done():
		t.Fatal("timeout")
	}
	return cl, conn
}

type quicReceiveStream interface {
	io.Reader
	SetReadDeadline(time.Time) error
}

func expectStreamReadReset(t *testing.T, str quicReceiveStream, errCode quic.StreamErrorCode) {
	t.Helper()

	str.SetReadDeadline(time.Now().Add(time.Second))
	_, err := str.Read([]byte{0})
	require.Error(t, err)
	if errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatal("didn't receive a stream reset")
	}
	var strErr *quic.StreamError
	require.ErrorAs(t, err, &strErr)
	require.Equal(t, errCode, strErr.ErrorCode)
}

type quicSendStream interface {
	io.Writer
	Context() context.Context
}

func expectStreamWriteReset(t *testing.T, str quicSendStream, errCode quic.StreamErrorCode) {
	t.Helper()

	select {
	case <-str.Context().Done():
	case <-time.After(time.Second):
		t.Fatal("timeout")
	}
	_, err := str.Write([]byte{0})
	require.Error(t, err)
	var strErr *quic.StreamError
	require.ErrorAs(t, err, &strErr)
	require.Equal(t, errCode, strErr.ErrorCode)
}

func encodeRequest(t *testing.T, req *http.Request) []byte {
	t.Helper()

	var buf bytes.Buffer
	rw := newRequestWriter()
	require.NoError(t, rw.WriteRequestHeader(&buf, req, false))
	if req.Body != nil {
		body, err := io.ReadAll(req.Body)
		require.NoError(t, err)
		buf.Write((&dataFrame{Length: uint64(len(body))}).Append(nil))
		buf.Write(body)
	}
	return buf.Bytes()
}

func decodeHeader(t *testing.T, r io.Reader) map[string][]string {
	t.Helper()

	fields := make(map[string][]string)
	decoder := qpack.NewDecoder(nil)

	frame, err := (&frameParser{r: r}).ParseNext()
	require.NoError(t, err)
	require.IsType(t, &headersFrame{}, frame)
	headersFrame := frame.(*headersFrame)
	data := make([]byte, headersFrame.Length)
	_, err = io.ReadFull(r, data)
	require.NoError(t, err)
	hfs, err := decoder.DecodeFull(data)
	require.NoError(t, err)
	for _, p := range hfs {
		fields[p.Name] = append(fields[p.Name], p.Value)
	}
	return fields
}
