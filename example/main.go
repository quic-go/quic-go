package main

import (
	"flag"
	"net/http"
	"os"

	"github.com/lucas-clemente/quic-go/h2quic"
)

func main() {
	bindTo := flag.String("bind", "localhost", "bind to")
	certPathDefault := os.Getenv("GOPATH") + "/src/github.com/lucas-clemente/quic-go/example/"
	certPath := flag.String("certpath", certPathDefault, "certificate directory")
	www := flag.String("www", "/var/www", "www data")
	flag.Parse()

	http.Handle("/", http.FileServer(http.Dir(*www)))

	server, err := h2quic.NewServer(*certPath)
	if err != nil {
		panic(err)
	}

	err = server.ListenAndServe(*bindTo+":6121", nil)
	if err != nil {
		panic(err)
	}
}
