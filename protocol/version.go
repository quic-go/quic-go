package protocol

// VersionNumber is a version number as int
type VersionNumber int

// The version numbers, making grepping easier
const (
	Version35 VersionNumber = 35 + iota
	Version36
	Version37
	VersionWhatever    = 0 // for when the version doesn't matter
	VersionUnsupported = -1
)

// SupportedVersions lists the versions that the server supports
// must be in sorted descending order
var SupportedVersions = []VersionNumber{
	Version37, Version36, Version35,
}

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
func IsSupportedVersion(supported []VersionNumber, v VersionNumber) bool {
	for _, t := range supported {
		if t == v {
			return true
		}
	}
	return false
}

// HighestSupportedVersion finds the highest version number that is both present in other and in SupportedVersions
// the versions in other do not need to be ordered
// it returns true and the version number, if there is one, otherwise false
func HighestSupportedVersion(other []VersionNumber) (bool, VersionNumber) {
	for _, v := range SupportedVersions {
		for _, ver := range other {
			if ver == v {
				return true, ver
			}
		}
	}

	return false, 0
}
