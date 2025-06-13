package quic

import (
	"context"
	"net"
	"testing"
	"time"

	tls "github.com/Noooste/utls"
)

func testDialPanic(t *testing.T, id QUICID) {

	quicSpec, err := QUICID2Spec(id)
	if err != nil {
		t.Fatal(err)
	}

	pktConn, err := net.ListenUDP("udp", nil)
	if err != nil {
		t.Fatal(err)
	}

	tr := &UTransport{Transport: &Transport{Conn: pktConn}, QUICSpec: &quicSpec}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	tr.Dial(ctx, &net.UDPAddr{IP: net.IP{127, 0, 0, 1}, Port: 1234}, &tls.Config{}, &Config{})

}

func TestDialPanic(t *testing.T) {

	for _, s := range []QUICID{QUICChrome_115, QUICFirefox_116} {
		testDialPanic(t, s)
	}

}
