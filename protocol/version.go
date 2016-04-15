package protocol

import (
	"bytes"

	"github.com/lucas-clemente/quic-go/utils"
)

// VersionNumber is a version number as int
type VersionNumber int

// SupportedVersions lists the versions that the server supports
var SupportedVersions = []VersionNumber{
	30,
	32,
}

// SupportedVersionsAsTags is needed for the SHLO crypto message
var SupportedVersionsAsTags []byte

// VersionNumberToTag maps version numbers ('32') to tags ('Q032')
func VersionNumberToTag(vn VersionNumber) uint32 {
	v := uint32(vn)
	return 'Q' + ((v/100%10)+'0')<<8 + ((v/10%10)+'0')<<16 + ((v%10)+'0')<<24
}

// VersionTagToNumber is built from VersionNumberToTag in init()
func VersionTagToNumber(v uint32) VersionNumber {
	return VersionNumber(((v>>8)&0xff-'0')*100 + ((v>>16)&0xff-'0')*10 + ((v>>24)&0xff - '0'))
}

// IsSupportedVersion returns true if the server supports this version
func IsSupportedVersion(v VersionNumber) bool {
	for _, t := range SupportedVersions {
		if t == v {
			return true
		}
	}
	return false
}

func init() {
	var b bytes.Buffer
	for _, v := range SupportedVersions {
		utils.WriteUint32(&b, VersionNumberToTag(v))
	}
	SupportedVersionsAsTags = b.Bytes()
}
