package main

import (
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/lucas-clemente/quic-go/http3"
	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/interop/http09"
	"golang.org/x/sync/errgroup"
)

var errUnsupported = errors.New("unsupported test case")

func main() {
	logFile, err := os.Create("/logs/log.txt")
	if err != nil {
		fmt.Printf("Could not create log file: %s\n", err.Error())
		os.Exit(1)
	}
	defer logFile.Close()
	log.SetOutput(logFile)

	testcase := os.Getenv("TESTCASE")
	if err := runTestcase(testcase); err != nil {
		if err == errUnsupported {
			fmt.Printf("unsupported test case: %s\n", testcase)
			os.Exit(127)
		}
		fmt.Printf("Downloading files failed: %s\n", err.Error())
		os.Exit(1)
	}
}

func runTestcase(testcase string) error {
	flag.Parse()
	urls := flag.Args()

	switch testcase {
	case "http3":
		r := &http3.RoundTripper{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
		defer r.Close()
		return downloadFiles(r, urls)
	case "handshake", "transfer", "retry":
	case "versionnegotiation":
		return runVersionNegotiationTest(urls)
	case "resumption":
		return runResumptionTest(urls)
	default:
		return errUnsupported
	}

	r := &http09.RoundTripper{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	defer r.Close()
	return downloadFiles(r, urls)
}

func runVersionNegotiationTest(urls []string) error {
	if len(urls) != 1 {
		return errors.New("expected at least 2 URLs")
	}
	protocol.SupportedVersions = []protocol.VersionNumber{0x1a2a3a4a}
	err := downloadFile(&http09.RoundTripper{}, urls[0])
	if err == nil {
		return errors.New("expected version negotiation to fail")
	}
	if !strings.Contains(err.Error(), "No compatible QUIC version found") {
		return fmt.Errorf("expect version negotiation error, got: %s", err.Error())
	}
	return nil
}

func runResumptionTest(urls []string) error {
	if len(urls) < 2 {
		return errors.New("expected at least 2 URLs")
	}
	csc := tls.NewLRUClientSessionCache(1)

	// do the first transfer
	r := &http09.RoundTripper{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
			ClientSessionCache: csc,
		},
	}
	if err := downloadFiles(r, urls[:1]); err != nil {
		return err
	}
	r.Close()

	// reestablish the connection, using the session ticket that the server (hopefully provided)
	r = &http09.RoundTripper{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
			ClientSessionCache: csc,
		},
	}
	defer r.Close()
	return downloadFiles(r, urls[1:])
}

func downloadFiles(cl http.RoundTripper, urls []string) error {
	var g errgroup.Group
	for _, u := range urls {
		url := u
		g.Go(func() error {
			return downloadFile(cl, url)
		})
	}
	return g.Wait()
}

func downloadFile(cl http.RoundTripper, url string) error {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	rsp, err := cl.RoundTrip(req)
	if err != nil {
		return err
	}
	defer rsp.Body.Close()

	file, err := os.Create("/downloads" + req.URL.Path)
	if err != nil {
		return err
	}
	defer file.Close()
	_, err = io.Copy(file, rsp.Body)
	return err
}
