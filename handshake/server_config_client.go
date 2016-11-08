package handshake

import (
	"bytes"
	"encoding/binary"
	"errors"
	"time"

	"github.com/lucas-clemente/quic-go/qerr"
)

type serverConfigClient struct {
	ID     []byte
	obit   []byte
	expiry time.Time
}

var (
	errMessageNotServerConfig = errors.New("ServerConfig must have TagSCFG")
)

// parseServerConfig parses a server config
func parseServerConfig(data []byte) (*serverConfigClient, error) {
	tag, tagMap, err := ParseHandshakeMessage(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	if tag != TagSCFG {
		return nil, errMessageNotServerConfig
	}

	scfg := &serverConfigClient{}
	err = scfg.parseValues(tagMap)
	if err != nil {
		return nil, err
	}

	return scfg, nil
}

func (s *serverConfigClient) parseValues(tagMap map[Tag][]byte) error {
	// SCID
	scfgID, ok := tagMap[TagSCID]
	if !ok {
		return qerr.Error(qerr.CryptoMessageParameterNotFound, "SCID")
	}
	if len(scfgID) != 16 {
		return qerr.Error(qerr.CryptoInvalidValueLength, "SCID")
	}
	s.ID = scfgID

	// KEXS
	// TODO: allow for P256 in the list
	// TODO: setup Key Exchange
	kexs, ok := tagMap[TagKEXS]
	if !ok {
		return qerr.Error(qerr.CryptoMessageParameterNotFound, "KEXS")
	}
	if len(kexs)%4 != 0 {
		return qerr.Error(qerr.CryptoInvalidValueLength, "KEXS")
	}
	if !bytes.Equal(kexs, []byte("C255")) {
		return qerr.Error(qerr.CryptoNoSupport, "KEXS")
	}

	// AEAD
	aead, ok := tagMap[TagAEAD]
	if !ok {
		return qerr.Error(qerr.CryptoMessageParameterNotFound, "AEAD")
	}
	if len(aead)%4 != 0 {
		return qerr.Error(qerr.CryptoInvalidValueLength, "AEAD")
	}
	var aesgFound bool
	for i := 0; i < len(aead)/4; i++ {
		if bytes.Equal(aead[4*i:4*i+4], []byte("AESG")) {
			aesgFound = true
			break
		}
	}
	if !aesgFound {
		return qerr.Error(qerr.CryptoNoSupport, "AEAD")
	}

	// PUBS
	// TODO: save this value
	pubs, ok := tagMap[TagPUBS]
	if !ok {
		return qerr.Error(qerr.CryptoMessageParameterNotFound, "PUBS")
	}
	if len(pubs) != 35 {
		return qerr.Error(qerr.CryptoInvalidValueLength, "PUBS")
	}

	// OBIT
	obit, ok := tagMap[TagOBIT]
	if !ok {
		return qerr.Error(qerr.CryptoMessageParameterNotFound, "OBIT")
	}
	if len(obit) != 8 {
		return qerr.Error(qerr.CryptoInvalidValueLength, "OBIT")
	}
	s.obit = obit

	// EXPY
	expy, ok := tagMap[TagEXPY]
	if !ok {
		return qerr.Error(qerr.CryptoMessageParameterNotFound, "EXPY")
	}
	if len(expy) != 8 {
		return qerr.Error(qerr.CryptoInvalidValueLength, "EXPY")
	}
	s.expiry = time.Unix(int64(binary.LittleEndian.Uint64(expy)), 0)

	// TODO: implement VER

	return nil
}
