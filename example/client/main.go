package main

import (
  "fmt"
  "net/http"
  "crypto/tls"
  "time"

  quic "github.com/lucas-clemente/quic-go"
  "github.com/lucas-clemente/quic-go/h2quic"
  "github.com/lucas-clemente/quic-go/internal/protocol"
)

func main() {
  url := "https://localhost:6121/demo/tiles"
  versions := protocol.SupportedVersions

  roundTripper := &h2quic.RoundTripper{
    QuicConfig: &quic.Config{Versions: versions},
    TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
  }
  hclient := &http.Client{
    Transport: roundTripper,
  }
  start := time.Now()
  _, err := hclient.Get(url)
  if err != nil {
    fmt.Println(err)
    panic("failed")
  } else {
    t := time.Now()
    elapsed := t.Sub(start)
    fmt.Println(elapsed)
  }
  roundTripper.Close()
}
