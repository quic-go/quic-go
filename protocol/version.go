package protocol

// VersionNumber is a version number as int
type VersionNumber int

// VersionNumberToTag maps version numbers ('32') to tags ('Q032')
func VersionNumberToTag(vn VersionNumber) uint32 {
	v := uint32(vn)
	return 'Q' + ((v/100%10)+'0')<<8 + ((v/10%10)+'0')<<16 + ((v%10)+'0')<<24
}

// VersionTagToNumber is built from VersionNumberToTag in init()
func VersionTagToNumber(v uint32) VersionNumber {
	return VersionNumber(((v>>8)&0xff-'0')*100 + ((v>>16)&0xff-'0')*10 + ((v>>24)&0xff - '0'))
}
