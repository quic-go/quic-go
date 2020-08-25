package helper

import (
	"crypto/sha1"
	"encoding/hex"
	"io/ioutil"
	"os"
	"path/filepath"
)

// NthBit gets the n-th bit of a byte (counting starts at 0).
func NthBit(val uint8, n int) bool {
	if n < 0 || n > 7 {
		panic("invalid value for n")
	}
	return val>>n&0x1 == 1
}

// WriteCorpusFile writes data to a corpus file in directory path.
// The filename is calculated from the SHA1 sum of the file contents.
func WriteCorpusFile(path string, data []byte) error {
	// create the directory, if it doesn't exist yet
	if _, err := os.Stat(path); os.IsNotExist(err) {
		if err := os.MkdirAll(path, os.ModePerm); err != nil {
			return err
		}
	}
	hash := sha1.Sum(data)
	return ioutil.WriteFile(filepath.Join(path, hex.EncodeToString(hash[:])), data, 0644)
}

// WriteCorpusFileWithPrefix writes data to a corpus file in directory path.
// In many fuzzers, the first n bytes are used to control.
// This function prepends n zero-bytes to the data.
func WriteCorpusFileWithPrefix(path string, data []byte, n int) error {
	return WriteCorpusFile(path, append(make([]byte, n), data...))
}
