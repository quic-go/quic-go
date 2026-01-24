package handshake

import (
	"crypto/tls"
	"net"
	"reflect"
)

func setupBaseConfigForServer(parent *tls.Config, fakeConn net.Conn) *tls.Config {
	child := parent.Clone()
	child.MinVersion = tls.VersionTLS13

	if child.GetCertificate != nil {
		child.GetCertificate = func(info *tls.ClientHelloInfo) (*tls.Certificate, error) {
			info.Conn = fakeConn
			return parent.GetCertificate(info)
		}
	}
	return child
}

func setupChildConfigForServer(originalConfig, parent, child *tls.Config) {
	if child.SessionTicketsDisabled {
		return
	}

	if child.WrapSession != nil && child.UnwrapSession != nil {
		return
	}

	if originalConfig != nil {
		sessionTicketKeys := reflect.ValueOf(child).Elem().FieldByName("sessionTicketKeys")
		if sessionTicketKeys.Kind() != reflect.Slice {
			return
		}
		if sessionTicketKeys.Len() != 0 {
			return
		}
		parent = originalConfig
	}

	if child.WrapSession == nil {
		child.WrapSession = parent.EncryptTicket
	}

	if child.UnwrapSession == nil {
		child.UnwrapSession = parent.DecryptTicket
	}
}

func setupConfigForServer(parent *tls.Config, localAddr, remoteAddr net.Addr) *tls.Config {
	fakeConn := &conn{localAddr: localAddr, remoteAddr: remoteAddr}
	child := setupBaseConfigForServer(parent, fakeConn)
	setupChildConfigForServer(nil, parent, child)

	// The tls.Config contains two callbacks that pass in a tls.ClientHelloInfo.
	// Since crypto/tls doesn't do it, we need to make sure to set the Conn field with a fake net.Conn
	// that allows the caller to get the local and the remote address.
	if child.GetConfigForClient != nil {
		child.GetConfigForClient = func(info *tls.ClientHelloInfo) (*tls.Config, error) {
			info.Conn = fakeConn

			gcfcParent, err := parent.GetConfigForClient(info)
			if err != nil {
				return nil, err
			}

			if gcfcParent == nil {
				return nil, nil
			}

			// we're returning a tls.Config here, so we need to apply this recursively
			gcfcChild := setupBaseConfigForServer(gcfcParent, fakeConn)
			setupChildConfigForServer(parent, gcfcParent, gcfcChild)
			return gcfcChild, nil
		}
	}

	return child
}
