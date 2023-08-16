//go:build !utls

package main

import (
	"net/http"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/interop/http09"
)

func runHTTP09Server(quicConf *quic.Config) error {
	server := http09.Server{
		Server: &http.Server{
			Addr:      ":443",
			TLSConfig: tlsConf,
		},
		QuicConfig: quicConf,
	}
	http.DefaultServeMux.Handle("/", http.FileServer(http.Dir("/www")))
	return server.ListenAndServe()
}
