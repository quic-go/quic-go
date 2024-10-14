package qlog

import (
	"bufio"
	"context"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/quic-go/quic-go/internal/utils"
	"github.com/quic-go/quic-go/logging"
)

// DefaultConnectionTracer creates a qlog file in the qlog directory specified by the QLOGDIR environment variable.
// File names are <odcid>_<perspective>.sqlog.
// Returns nil if QLOGDIR is not set.
func DefaultConnectionTracer(_ context.Context, p logging.Perspective, connID logging.ConnectionID) *logging.ConnectionTracer {
	var label string
	switch p {
	case logging.PerspectiveClient:
		label = "client"
	case logging.PerspectiveServer:
		label = "server"
	}
	return qlogDirTracer(p, connID, label)
}

// qlogDirTracer creates a qlog file in the qlog directory specified by the QLOGDIR environment variable.
// File names are <odcid>_<label>.sqlog.
// Returns nil if QLOGDIR is not set.
func qlogDirTracer(p logging.Perspective, connID logging.ConnectionID, label string) *logging.ConnectionTracer {
	qlogDir := os.Getenv("QLOGDIR")
	if qlogDir == "" {
		return nil
	}
	if _, err := os.Stat(qlogDir); os.IsNotExist(err) {
		if err := os.MkdirAll(qlogDir, 0o755); err != nil {
			log.Fatalf("failed to create qlog dir %s: %v", qlogDir, err)
		}
	}
	path := fmt.Sprintf("%s/%s_%s.sqlog", strings.TrimRight(qlogDir, "/"), connID, label)
	f, err := os.Create(path)
	if err != nil {
		log.Printf("Failed to create qlog file %s: %s", path, err.Error())
		return nil
	}
	return NewConnectionTracer(utils.NewBufferedWriteCloser(bufio.NewWriter(f), f), p, connID)
}
