package crypto

import (
	"github.com/bifurcation/mint"
	"github.com/lucas-clemente/quic-go/internal/protocol"
)

const (
	clientExporterLabel = "EXPORTER-QUIC client 1-RTT Secret"
	serverExporterLabel = "EXPORTER-QUIC server 1-RTT Secret"
)

// MintController is an interface that bundles all methods needed to interact with mint
type MintController interface {
	Handshake() mint.Alert
	GetCipherSuite() mint.CipherSuiteParams
	ComputeExporter(label string, context []byte, keyLength int) ([]byte, error)
}

// DeriveAESKeys derives the AES keys and creates a matching AES-GCM AEAD instance
func DeriveAESKeys(mc MintController, pers protocol.Perspective) (AEAD, error) {
	var myLabel, otherLabel string
	if pers == protocol.PerspectiveClient {
		myLabel = clientExporterLabel
		otherLabel = serverExporterLabel
	} else {
		myLabel = serverExporterLabel
		otherLabel = clientExporterLabel
	}
	myKey, myIV, err := computeKeyAndIV(mc, myLabel)
	if err != nil {
		return nil, err
	}
	otherKey, otherIV, err := computeKeyAndIV(mc, otherLabel)
	if err != nil {
		return nil, err
	}
	return NewAEADAESGCM(otherKey, myKey, otherIV, myIV)
}

func computeKeyAndIV(mc MintController, label string) (key, iv []byte, err error) {
	cs := mc.GetCipherSuite()
	secret, err := mc.ComputeExporter(label, nil, cs.Hash.Size())
	if err != nil {
		return nil, nil, err
	}
	key = mint.HkdfExpandLabel(cs.Hash, secret, "key", nil, cs.KeyLen)
	iv = mint.HkdfExpandLabel(cs.Hash, secret, "iv", nil, cs.IvLen)
	return key, iv, nil
}
