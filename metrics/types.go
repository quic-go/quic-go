package metrics

import "github.com/lucas-clemente/quic-go/logging"

type perspective logging.Perspective

func (p perspective) String() string {
	switch logging.Perspective(p) {
	case logging.PerspectiveClient:
		return "client"
	case logging.PerspectiveServer:
		return "server"
	default:
		panic("unknown perspective")
	}
}
