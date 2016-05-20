package protocol

import (
	"bytes"
	"encoding/binary"
)

// VersionNumber is a version number as int
type VersionNumber int

// SupportedVersions lists the versions that the server supports
var SupportedVersions = []VersionNumber{
	30, 31, 32, 33,
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
		s := make([]byte, 4)
		binary.LittleEndian.PutUint32(s, VersionNumberToTag(v))
		b.Write(s)
	}
	SupportedVersionsAsTags = b.Bytes()
}
