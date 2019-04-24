package main

import (
  "fmt"
  "net/http"
  "crypto/tls"
  "strconv"
  "time"
  //"syscall/js"
  "io/ioutil"

  quic "github.com/lucas-clemente/quic-go"
  "github.com/lucas-clemente/quic-go/h2quic"
  "github.com/lucas-clemente/quic-go/internal/protocol"
)
const addr = "localhost:4242"

func main() {

  //session, err := quic.DialAddr(addr, &tls.Config{InsecureSkipVerify: true}, nil)
  //if err != nil {
    //panic(err)
  //}
  //stream, err := session.OpenStreamSync()
  //if err != nil {
    //panic(err)
  //}
  //message := "fasfjkaslfaksjflaijsfioakjcsclcansoiljgineiojalijsfklajsflakhsflaihsfoilhafeofnliaefhialclhksnlajsofluahsrlhilaflfehkglejgklh;oobar"
  //for i := 0; i < 1000; i++ {
    //fmt.Println("Client: Sending", i)
    //_, err = stream.Write([]byte(message))
    //if err != nil {
      //panic(err)
    //}
  //}

 versions := protocol.SupportedVersions
  roundTripper := &h2quic.RoundTripper{
    QuicConfig: &quic.Config{Versions: versions},
    TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
  }
  hclient := &http.Client{
    Transport: roundTripper,
  }
  p := true
  start := 0
  stop := 1000
  for i := start; i < stop; i++ {
    t0 := time.Now()
    url := "https://stalepopcorn.club/static/files/file"+strconv.Itoa(i)+".html"
    //url := "https://stalepopcorn.club/static/files/file0.html"
    //url := "https://stalepopcorn.club/random"
    fmt.Println(url)
    if i == 99 {
      fmt.Println("READY")
      //for t := 0; t < 10; t++ {
        ////time.Sleep(time.Second * 10) 
        //domUDP := js.Global().Get("document").Get("udp")
        //ui8 := make([]uint8, 100)
        //for j := 0; j < 100; j++ {
          //ui8[j] = 65
        //}
        //domUDP.Call("send", js.TypedArrayOf(ui8).Value)
      //}
    }
    resp, err := hclient.Get(url)
    body, err := ioutil.ReadAll(resp.Body)
    fmt.Println(len(body))
    resp.Body.Close()
    if err != nil {
      fmt.Println(err)
      panic("failed")
    } else {
      t1 := time.Now()
      elapsed := t1.Sub(t0)
      if (p) {
        fmt.Println(elapsed)
      }
      p = true
    }
  }
  fmt.Println("Done!")
  roundTripper.Close()
}
