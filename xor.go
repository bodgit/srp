//go:build go1.20

package srp

import "crypto/subtle"

func xorBytes(dst, x, y []byte) int {
	return subtle.XORBytes(dst, x, y)
}
