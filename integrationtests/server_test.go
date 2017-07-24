package integrationtests

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"io/ioutil"
	"math/big"
	mrand "math/rand"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"time"

	"github.com/lucas-clemente/quic-go/h2quic"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/gbytes"
	. "github.com/onsi/gomega/gexec"
)

var _ = Describe("Server tests", func() {
	mrand.Seed(time.Now().UnixNano())

	var (
		serverPort string
		tmpDir     string
		session    *Session
		client     *http.Client
	)

	generateCA := func() (*rsa.PrivateKey, *x509.Certificate) {
		key, err := rsa.GenerateKey(rand.Reader, 1024)
		Expect(err).ToNot(HaveOccurred())

		templateRoot := &x509.Certificate{
			SerialNumber: big.NewInt(1),
			NotBefore:    time.Now().Add(-time.Hour),
			NotAfter:     time.Now().Add(time.Hour),
			IsCA:         true,
			BasicConstraintsValid: true,
		}
		certDER, err := x509.CreateCertificate(rand.Reader, templateRoot, templateRoot, &key.PublicKey, key)
		Expect(err).ToNot(HaveOccurred())
		cert, err := x509.ParseCertificate(certDER)
		Expect(err).ToNot(HaveOccurred())
		return key, cert
	}

	// prepare the file such that it can be by the quic_server
	// some HTTP headers neeed to be prepended, see https://www.chromium.org/quic/playing-with-quic
	createDownloadFile := func(filename string, data []byte) {
		dataDir := filepath.Join(tmpDir, "quic.clemente.io")
		err := os.Mkdir(dataDir, 0777)
		Expect(err).ToNot(HaveOccurred())
		f, err := os.Create(filepath.Join(dataDir, filename))
		Expect(err).ToNot(HaveOccurred())
		defer f.Close()
		_, err = f.Write([]byte("HTTP/1.1 200 OK\n"))
		Expect(err).ToNot(HaveOccurred())
		_, err = f.Write([]byte("Content-Type: text/html\n"))
		Expect(err).ToNot(HaveOccurred())
		_, err = f.Write([]byte("X-Original-Url: https://quic.clemente.io:" + serverPort + "/" + filename + "\n"))
		Expect(err).ToNot(HaveOccurred())
		_, err = f.Write([]byte("Content-Length: " + strconv.Itoa(len(data)) + "\n\n"))
		Expect(err).ToNot(HaveOccurred())
		_, err = f.Write(data)
		Expect(err).ToNot(HaveOccurred())
	}

	// download files must be create *before* the quic_server is started
	// the quic_server reads its data dir on startup, and only serves those files that were already present then
	startServer := func() {
		go func() {
			defer GinkgoRecover()
			var err error
			command := exec.Command(
				serverPath,
				"--quic_response_cache_dir="+filepath.Join(tmpDir, "quic.clemente.io"),
				"--key_file="+filepath.Join(tmpDir, "key.pkcs8"),
				"--certificate_file="+filepath.Join(tmpDir, "cert.pem"),
				"--port="+serverPort,
			)
			session, err = Start(command, nil, GinkgoWriter)
			Expect(err).NotTo(HaveOccurred())
		}()
	}

	stopServer := func() {
		session.Kill()
	}

	BeforeEach(func() {
		serverPort = strconv.Itoa(20000 + int(mrand.Int31n(10000)))

		var err error
		tmpDir, err = ioutil.TempDir("", "quic-server-certs")
		Expect(err).ToNot(HaveOccurred())

		// generate an RSA key pair for the server
		key, err := rsa.GenerateKey(rand.Reader, 1024)
		Expect(err).ToNot(HaveOccurred())

		// save the private key in PKCS8 format to disk (required by quic_server)
		pkcs8key, err := asn1.Marshal(struct { // copied from the x509 package
			Version    int
			Algo       pkix.AlgorithmIdentifier
			PrivateKey []byte
		}{
			PrivateKey: x509.MarshalPKCS1PrivateKey(key),
			Algo: pkix.AlgorithmIdentifier{
				Algorithm:  asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1},
				Parameters: asn1.RawValue{Tag: 5},
			},
		})
		Expect(err).ToNot(HaveOccurred())
		f, err := os.Create(filepath.Join(tmpDir, "key.pkcs8"))
		Expect(err).ToNot(HaveOccurred())
		_, err = f.Write(pkcs8key)
		Expect(err).ToNot(HaveOccurred())
		f.Close()

		// generate a Certificate Authority
		// this CA is used to sign the server's key
		// it is set as a valid CA in the QUIC client
		rootKey, CACert := generateCA()
		// generate the server certificate
		template := &x509.Certificate{
			SerialNumber: big.NewInt(1),
			NotBefore:    time.Now().Add(-30 * time.Minute),
			NotAfter:     time.Now().Add(30 * time.Minute),
			Subject:      pkix.Name{CommonName: "quic.clemente.io"},
		}
		certDER, err := x509.CreateCertificate(rand.Reader, template, CACert, &key.PublicKey, rootKey)
		Expect(err).ToNot(HaveOccurred())
		// save the certificate to disk
		certOut, err := os.Create(filepath.Join(tmpDir, "cert.pem"))
		Expect(err).ToNot(HaveOccurred())
		pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: certDER})
		certOut.Close()

		// prepare the h2quic.client
		certPool := x509.NewCertPool()
		certPool.AddCert(CACert)
		client = &http.Client{
			Transport: &h2quic.RoundTripper{
				TLSClientConfig: &tls.Config{RootCAs: certPool},
			},
		}
	})

	AfterEach(func() {
		Expect(tmpDir).ToNot(BeEmpty())
		err := os.RemoveAll(tmpDir)
		Expect(err).ToNot(HaveOccurred())
		tmpDir = ""
	})

	It("downloads a hello", func() {
		data := []byte("Hello world!\n")
		createDownloadFile("hello", data)

		startServer()
		defer stopServer()

		rsp, err := client.Get("https://quic.clemente.io:" + serverPort + "/hello")
		Expect(err).ToNot(HaveOccurred())
		Expect(rsp.StatusCode).To(Equal(200))
		body, err := ioutil.ReadAll(gbytes.TimeoutReader(rsp.Body, 5*time.Second))
		Expect(err).ToNot(HaveOccurred())
		Expect(body).To(Equal(data))
	})

	It("downloads a small file", func() {
		dataMan.GenerateData(dataLen)
		data := dataMan.GetData()
		createDownloadFile("file.dat", data)

		startServer()
		defer stopServer()

		rsp, err := client.Get("https://quic.clemente.io:" + serverPort + "/file.dat")
		Expect(err).ToNot(HaveOccurred())
		Expect(rsp.StatusCode).To(Equal(200))
		body, err := ioutil.ReadAll(gbytes.TimeoutReader(rsp.Body, 5*time.Second))
		Expect(err).ToNot(HaveOccurred())
		Expect(body).To(Equal(data))
	})

	It("downloads a large file", func() {
		dataMan.GenerateData(dataLongLen)
		data := dataMan.GetData()
		createDownloadFile("file.dat", data)

		startServer()
		defer stopServer()

		rsp, err := client.Get("https://quic.clemente.io:" + serverPort + "/file.dat")
		Expect(err).ToNot(HaveOccurred())
		Expect(rsp.StatusCode).To(Equal(200))
		body, err := ioutil.ReadAll(gbytes.TimeoutReader(rsp.Body, 20*time.Second))
		Expect(err).ToNot(HaveOccurred())
		Expect(body).To(Equal(data))
	})
})
