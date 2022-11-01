//go:build !1.20

package srp

func xorBytes(dst, x, y []byte) int {
	n := len(x)

	if len(y) < n {
		n = len(y)
	}

	if len(dst) < n {
		n = len(dst)
	}

	if n == 0 {
		return n
	}

	_ = dst[n-1]
	_ = x[n-1]
	_ = y[n-1]

	for i := 0; i < n; i++ {
		dst[i] = x[i] ^ y[i]
	}

	return n
}
