package http3

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/quic-go/qpack"
	"github.com/quic-go/quic-go/integrationtests/tools"

	"github.com/stretchr/testify/require"
)

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

func getTLSConfig() *tls.Config       { return tlsConfig.Clone() }
func getTLSClientConfig() *tls.Config { return tlsClientConfig.Clone() }

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
