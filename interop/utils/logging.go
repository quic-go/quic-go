package utils

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"os"
	"strings"

	"github.com/quic-go/quic-go/internal/utils"
	"github.com/quic-go/quic-go/logging"
)

// GetSSLKeyLog creates a file for the TLS key log
func GetSSLKeyLog() (io.WriteCloser, error) {
	filename := os.Getenv("SSLKEYLOGFILE")
	if len(filename) == 0 {
		return nil, nil
	}
	f, err := os.Create(filename)
	if err != nil {
		return nil, err
	}
	return f, nil
}

// GetQLOGWriter creates the QLOGDIR and returns the GetLogWriter callback
func GetQLOGWriter() (func(perspective logging.Perspective, connID []byte) io.WriteCloser, error) {
	qlogDir := os.Getenv("QLOGDIR")
	if len(qlogDir) == 0 {
		return nil, nil
	}
	if _, err := os.Stat(qlogDir); os.IsNotExist(err) {
		if err := os.MkdirAll(qlogDir, 0o666); err != nil {
			return nil, fmt.Errorf("failed to create qlog dir %s: %s", qlogDir, err.Error())
		}
	}
	return func(_ logging.Perspective, connID []byte) io.WriteCloser {
		path := fmt.Sprintf("%s/%x.qlog", strings.TrimRight(qlogDir, "/"), connID)
		f, err := os.Create(path)
		if err != nil {
			log.Printf("Failed to create qlog file %s: %s", path, err.Error())
			return nil
		}
		log.Printf("Created qlog file: %s\n", path)
		return utils.NewBufferedWriteCloser(bufio.NewWriter(f), f)
	}, nil
}
