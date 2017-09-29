package handshake

import (
	"errors"
	"fmt"

	"github.com/bifurcation/mint"
	"github.com/bifurcation/mint/syntax"
	"github.com/lucas-clemente/quic-go/internal/protocol"
)

type extensionHandlerClient struct {
	params *paramsNegotiator
}

var _ mint.AppExtensionHandler = &extensionHandlerClient{}

func newExtensionHandlerClient(params *paramsNegotiator) *extensionHandlerClient {
	return &extensionHandlerClient{params: params}
}

func (h *extensionHandlerClient) Send(hType mint.HandshakeType, el *mint.ExtensionList) error {
	if hType != mint.HandshakeTypeClientHello {
		return nil
	}

	data, err := syntax.Marshal(clientHelloTransportParameters{
		NegotiatedVersion: uint32(protocol.VersionTLS),
		InitialVersion:    uint32(protocol.VersionTLS),
		Parameters:        h.params.GetTransportParameters(),
	})
	if err != nil {
		return err
	}
	return el.Add(&tlsExtensionBody{data})
}

func (h *extensionHandlerClient) Receive(hType mint.HandshakeType, el *mint.ExtensionList) error {
	ext := &tlsExtensionBody{}
	found := el.Find(ext)

	if hType != mint.HandshakeTypeEncryptedExtensions && hType != mint.HandshakeTypeNewSessionTicket {
		if found {
			return fmt.Errorf("Unexpected QUIC extension in handshake message %d", hType)
		}
		return nil
	}
	if hType == mint.HandshakeTypeNewSessionTicket {
		// the extension it's optional in the NewSessionTicket message
		// TODO: handle this
		return nil
	}

	// hType == mint.HandshakeTypeEncryptedExtensions
	if !found {
		return errors.New("EncryptedExtensions message didn't contain a QUIC extension")
	}

	eetp := &encryptedExtensionsTransportParameters{}
	if _, err := syntax.Unmarshal(ext.data, eetp); err != nil {
		return err
	}
	// TODO: check versions

	// check that the server sent the stateless reset token
	var foundStatelessResetToken bool
	for _, p := range eetp.Parameters {
		if p.Parameter == statelessResetTokenParameterID {
			if len(p.Value) != 16 {
				return fmt.Errorf("wrong length for stateless_reset_token: %d (expected 16)", len(p.Value))
			}
			foundStatelessResetToken = true
			// TODO: handle this value
		}
	}
	if !foundStatelessResetToken {
		// TODO: return the right error here
		return errors.New("server didn't sent stateless_reset_token")
	}
	return h.params.SetFromTransportParameters(eetp.Parameters)
}
