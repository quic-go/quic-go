package protocol

import (
	"fmt"
)

// VersionNumber is a version number as int
type VersionNumber int

// gquicVersion0 is the "base" for gQUIC versions
// e.g. version 39 is gquicVersion + 0x39
const gquicVersion0 = 0x51303300

// The version numbers, making grepping easier
const (
	Version37 VersionNumber = gquicVersion0 + 0x37 + iota
	Version38
	Version39
	VersionTLS         VersionNumber = 101
	VersionWhatever    VersionNumber = 0 // for when the version doesn't matter
	VersionUnsupported VersionNumber = -1
	VersionUnknown     VersionNumber = -2
)

// SupportedVersions lists the versions that the server supports
// must be in sorted descending order
var SupportedVersions = []VersionNumber{
	Version39,
	Version38,
	Version37,
}

// UsesTLS says if this QUIC version uses TLS 1.3 for the handshake
func (vn VersionNumber) UsesTLS() bool {
	return vn == VersionTLS
}

func (vn VersionNumber) String() string {
	switch vn {
	case VersionWhatever:
		return "whatever"
	case VersionUnsupported:
		return "unsupported"
	case VersionUnknown:
		return "unknown"
	case VersionTLS:
		return "TLS dev version (WIP)"
	default:
		if vn > gquicVersion0 && vn <= gquicVersion0+0x99 {
			return fmt.Sprintf("gQUIC %x", uint32(vn-gquicVersion0))
		}
		return fmt.Sprintf("%d", vn)
	}
}

// ToAltSvc returns the representation of the version for the H2 Alt-Svc parameters
func (vn VersionNumber) ToAltSvc() string {
	if vn > gquicVersion0 && vn <= gquicVersion0+0x99 {
		return fmt.Sprintf("%x", uint32(vn-gquicVersion0))
	}
	return fmt.Sprintf("%d", vn)
}

// IsSupportedVersion returns true if the server supports this version
func IsSupportedVersion(supported []VersionNumber, v VersionNumber) bool {
	for _, t := range supported {
		if t == v {
			return true
		}
	}
	return false
}

// ChooseSupportedVersion finds the best version in the overlap of ours and theirs
// ours is a slice of versions that we support, sorted by our preference (descending)
// theirs is a slice of versions offered by the peer. The order does not matter
// if no suitable version is found, it returns VersionUnsupported
func ChooseSupportedVersion(ours, theirs []VersionNumber) VersionNumber {
	for _, ourVer := range ours {
		for _, theirVer := range theirs {
			if ourVer == theirVer {
				return ourVer
			}
		}
	}
	return VersionUnsupported
}
