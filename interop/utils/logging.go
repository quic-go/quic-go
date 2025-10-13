package utils

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log"
	"os"
	"strings"

	"github.com/quic-go/quic-go"
	h3qlog "github.com/quic-go/quic-go/http3/qlog"
	"github.com/quic-go/quic-go/internal/utils"
	"github.com/quic-go/quic-go/qlog"
	"github.com/quic-go/quic-go/qlogwriter"
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

// NewQLOGConnectionTracer create a qlog file in QLOGDIR
func NewQLOGConnectionTracer(_ context.Context, isClient bool, connID quic.ConnectionID) qlogwriter.Trace {
	qlogDir := os.Getenv("QLOGDIR")
	if len(qlogDir) == 0 {
		return nil
	}
	if _, err := os.Stat(qlogDir); os.IsNotExist(err) {
		if err := os.MkdirAll(qlogDir, 0o666); err != nil {
			log.Fatalf("failed to create qlog dir %s: %v", qlogDir, err)
		}
	}
	path := fmt.Sprintf("%s/%s.sqlog", strings.TrimRight(qlogDir, "/"), connID)
	f, err := os.Create(path)
	if err != nil {
		log.Printf("Failed to create qlog file %s: %s", path, err.Error())
		return nil
	}
	log.Printf("Created qlog file: %s\n", path)
	fileSeq := qlogwriter.NewConnectionFileSeq(
		utils.NewBufferedWriteCloser(bufio.NewWriter(f), f),
		isClient,
		connID,
		[]string{qlog.EventSchema, h3qlog.EventSchema},
	)
	go fileSeq.Run()
	return fileSeq
}
