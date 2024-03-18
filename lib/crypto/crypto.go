package VedCrypto

import "crypto/sha256"

func Hash(ms ...[]byte) []byte {
	h := sha256.New()
	for _, m := range ms {
		h.Write(m)
	}
	return h.Sum(nil)
}
