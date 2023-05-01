package tools

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"os"

	"github.com/quic-go/quic-go/internal/utils"
	"github.com/quic-go/quic-go/logging"
	"github.com/quic-go/quic-go/qlog"
)

func NewQlogger(logger io.Writer) logging.Tracer {
	return qlog.NewTracer(func(p logging.Perspective, connectionID []byte) io.WriteCloser {
		role := "server"
		if p == logging.PerspectiveClient {
			role = "client"
		}
		filename := fmt.Sprintf("log_%x_%s.qlog", connectionID, role)
		fmt.Fprintf(logger, "Creating %s.\n", filename)
		f, err := os.Create(filename)
		if err != nil {
			log.Fatalf("failed to create qlog file: %s", err)
			return nil
		}
		bw := bufio.NewWriter(f)
		return utils.NewBufferedWriteCloser(bw, f)
	})
}
