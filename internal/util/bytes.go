package util

import (
	"encoding/hex"
	"fmt"
	"math/big"
	"regexp"
)

func BytesFromHexString(s string) ([]byte, error) {
	b, err := hex.DecodeString(regexp.MustCompile("[^0-9a-fA-F]").ReplaceAllString(s, ""))
	if err != nil {
		return nil, fmt.Errorf("unable to decode string: %w", err)
	}

	return b, nil
}

func Pad(x *big.Int, n int) []byte {
	b := x.Bytes()
	if len(b) < n {
		z := n - len(b)
		p := make([]byte, n)

		for i := 0; i < z; i++ {
			p[i] = 0
		}

		copy(p[z:], b)
		b = p
	}

	return b
}
