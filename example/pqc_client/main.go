// Command pqc_client connects to pqc_server and echoes a message, selecting the
// post-quantum key exchange purely through tls.Config.CurvePreferences.
package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"log"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/pqctls"
)

func main() {
	addr := flag.String("addr", "localhost:4433", "server address")
	mode := flag.String("mode", "mlkem768", "classical | mlkem768 | mlkem1024 | hybrid")
	flag.Parse()

	curve, err := clientCurve(*mode)
	if err != nil {
		log.Fatal(err)
	}

	tlsConf := &tls.Config{
		InsecureSkipVerify: true, // self-signed certificates in this demo
		NextProtos:         []string{"pqc-echo"},
		CurvePreferences:   []tls.CurveID{curve},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	conn, err := quic.DialAddr(ctx, *addr, tlsConf, nil)
	if err != nil {
		log.Fatal(err)
	}
	defer conn.CloseWithError(0, "")

	cs := conn.ConnectionState().TLS
	fmt.Printf("connected: curve=0x%04x cipher=0x%04x\n", uint16(cs.CurveID), cs.CipherSuite)

	str, err := conn.OpenStreamSync(ctx)
	if err != nil {
		log.Fatal(err)
	}
	if _, err := str.Write([]byte("hello post-quantum world")); err != nil {
		log.Fatal(err)
	}
	if err := str.Close(); err != nil {
		log.Fatal(err)
	}

	echo, err := io.ReadAll(str)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("echo: %s\n", echo)
}

func clientCurve(mode string) (tls.CurveID, error) {
	switch mode {
	case "classical":
		return tls.X25519, nil
	case "mlkem768":
		return pqctls.MLKEM768, nil
	case "mlkem1024":
		return pqctls.MLKEM1024, nil
	case "hybrid":
		return pqctls.X25519MLKEM768, nil
	default:
		return 0, fmt.Errorf("unknown mode %q", mode)
	}
}
