package crypto

import (
	"hash/fnv"
	"sync"
)

var (
	compressedCertsCache      = map[uint64][]byte{}
	compressedCertsCacheMutex sync.RWMutex
)

func getCompressedCert(chain [][]byte, pCommonSetHashes, pCachedHashes []byte) ([]byte, error) {
	// Hash all inputs
	hash := fnv.New64a()
	for _, v := range chain {
		hash.Write(v)
	}
	hash.Write(pCommonSetHashes)
	hash.Write(pCachedHashes)
	hashRes := hash.Sum64()

	compressedCertsCacheMutex.RLock()
	result, isCached := compressedCertsCache[hashRes]
	compressedCertsCacheMutex.RUnlock()
	if isCached {
		return result, nil
	}

	compressedCertsCacheMutex.Lock()
	defer compressedCertsCacheMutex.Unlock()
	result, isCached = compressedCertsCache[hashRes]
	if isCached {
		return result, nil
	}
	cached, err := compressChain(chain, pCommonSetHashes, pCachedHashes)
	if err != nil {
		return nil, err
	}
	compressedCertsCache[hashRes] = cached
	return cached, nil
}
