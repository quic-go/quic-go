package handshake

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/bifurcation/mint"
	"github.com/bifurcation/mint/syntax"
	"github.com/lucas-clemente/quic-go/internal/protocol"
)

type extensionHandlerServer struct {
	params *paramsNegotiator

	supportedVersions []protocol.VersionNumber
}

var _ mint.AppExtensionHandler = &extensionHandlerServer{}

func newExtensionHandlerServer(params *paramsNegotiator, supportedVersions []protocol.VersionNumber) *extensionHandlerServer {
	return &extensionHandlerServer{
		params:            params,
		supportedVersions: supportedVersions,
	}
}

func (h *extensionHandlerServer) Send(hType mint.HandshakeType, el *mint.ExtensionList) error {
	if hType != mint.HandshakeTypeEncryptedExtensions {
		return nil
	}

	transportParams := append(
		h.params.GetTransportParameters(),
		transportParameter{statelessResetTokenParameterID, bytes.Repeat([]byte{42}, 16)},
	)
	supportedVersions := make([]uint32, len(h.supportedVersions))
	for i, v := range h.supportedVersions {
		supportedVersions[i] = uint32(v)
	}
	data, err := syntax.Marshal(encryptedExtensionsTransportParameters{
		SupportedVersions: supportedVersions,
		Parameters:        transportParams,
	})
	if err != nil {
		return err
	}
	return el.Add(&tlsExtensionBody{data})
}

func (h *extensionHandlerServer) Receive(hType mint.HandshakeType, el *mint.ExtensionList) error {
	ext := &tlsExtensionBody{}
	found := el.Find(ext)

	if hType != mint.HandshakeTypeClientHello {
		if found {
			return fmt.Errorf("Unexpected QUIC extension in handshake message %d", hType)
		}
		return nil
	}

	if !found {
		return errors.New("ClientHello didn't contain a QUIC extension")
	}
	chtp := &clientHelloTransportParameters{}
	if _, err := syntax.Unmarshal(ext.data, chtp); err != nil {
		return err
	}
	// TODO: check versions
	for _, p := range chtp.Parameters {
		if p.Parameter == statelessResetTokenParameterID {
			// TODO: return the correct error type
			return errors.New("client sent a stateless reset token")
		}
	}
	return h.params.SetFromTransportParameters(chtp.Parameters)
}
