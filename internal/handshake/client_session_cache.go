package handshake

import (
	"crypto/tls"
	"encoding/asn1"
	"unsafe"

	"github.com/marten-seemann/qtls"
)

type nonceField struct {
	Nonce   []byte
	AppData []byte
}

type clientSessionCache struct {
	tls.ClientSessionCache

	getAppData func() []byte
	setAppData func([]byte)
}

func newClientSessionCache(cache tls.ClientSessionCache, get func() []byte, set func([]byte)) *clientSessionCache {
	return &clientSessionCache{
		ClientSessionCache: cache,
		getAppData:         get,
		setAppData:         set,
	}
}

var _ qtls.ClientSessionCache = &clientSessionCache{}

func (c *clientSessionCache) Get(sessionKey string) (*qtls.ClientSessionState, bool) {
	sess, ok := c.ClientSessionCache.Get(sessionKey)
	if sess == nil {
		return nil, ok
	}
	// qtls.ClientSessionState is identical to the tls.ClientSessionState.
	// In order to allow users of quic-go to use a tls.Config,
	// we need this workaround to use the ClientSessionCache.
	// In unsafe.go we check that the two structs are actually identical.
	tlsSessBytes := (*[unsafe.Sizeof(*sess)]byte)(unsafe.Pointer(sess))[:]
	var session clientSessionState
	sessBytes := (*[unsafe.Sizeof(session)]byte)(unsafe.Pointer(&session))[:]
	copy(sessBytes, tlsSessBytes)
	var nf nonceField
	if _, err := asn1.Unmarshal(session.nonce, &nf); err != nil {
		return nil, false
	}
	c.setAppData(nf.AppData)
	session.nonce = nf.Nonce
	var qtlsSession qtls.ClientSessionState
	qtlsSessBytes := (*[unsafe.Sizeof(qtlsSession)]byte)(unsafe.Pointer(&qtlsSession))[:]
	copy(qtlsSessBytes, sessBytes)
	return &qtlsSession, ok
}

func (c *clientSessionCache) Put(sessionKey string, cs *qtls.ClientSessionState) {
	if cs == nil {
		c.ClientSessionCache.Put(sessionKey, nil)
		return
	}
	// qtls.ClientSessionState is identical to the tls.ClientSessionState.
	// In order to allow users of quic-go to use a tls.Config,
	// we need this workaround to use the ClientSessionCache.
	// In unsafe.go we check that the two structs are actually identical.
	qtlsSessBytes := (*[unsafe.Sizeof(*cs)]byte)(unsafe.Pointer(cs))[:]
	var session clientSessionState
	sessBytes := (*[unsafe.Sizeof(session)]byte)(unsafe.Pointer(&session))[:]
	copy(sessBytes, qtlsSessBytes)
	nonce, err := asn1.Marshal(nonceField{
		Nonce:   session.nonce,
		AppData: c.getAppData(),
	})
	if err != nil { // marshaling
		panic(err)
	}
	session.nonce = nonce
	var tlsSession tls.ClientSessionState
	tlsSessBytes := (*[unsafe.Sizeof(tlsSession)]byte)(unsafe.Pointer(&tlsSession))[:]
	copy(tlsSessBytes, sessBytes)
	c.ClientSessionCache.Put(sessionKey, &tlsSession)
}
