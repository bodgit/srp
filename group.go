package srp

import (
	"fmt"
	"math/big"

	"github.com/bodgit/srp/internal/rfc5054"
	"github.com/bodgit/srp/internal/util"
)

// Group represents the SRP group parameters.
type Group struct {
	G    *big.Int
	N    *big.Int
	Size int
}

var rfcGroups = map[int]*Group{
	1024: util.Must(NewGroup(2, 1024, rfc5054.Hex1024)),  //nolint:gomnd
	1536: util.Must(NewGroup(2, 1536, rfc5054.Hex1536)),  //nolint:gomnd
	2048: util.Must(NewGroup(2, 2048, rfc5054.Hex2048)),  //nolint:gomnd
	3072: util.Must(NewGroup(5, 3072, rfc5054.Hex3072)),  //nolint:gomnd
	4096: util.Must(NewGroup(5, 4096, rfc5054.Hex4096)),  //nolint:gomnd
	6144: util.Must(NewGroup(5, 6144, rfc5054.Hex6144)),  //nolint:gomnd
	8192: util.Must(NewGroup(19, 8192, rfc5054.Hex8192)), //nolint:gomnd
}

// NewGroup returns a Group with the generator g, and a prime of size bits set
// to the bytes decoded from s.
func NewGroup(g int64, size int, s string) (*Group, error) {
	b, err := util.BytesFromHexString(s)
	if err != nil {
		return nil, fmt.Errorf("unable to convert hex string to bytes: %w", err)
	}

	group := &Group{
		G:    big.NewInt(g),
		N:    new(big.Int).SetBytes(b),
		Size: size >> 3, //nolint:gomnd
	}

	return group, nil
}

// GetGroup returns the RFC 5054 group for the prime of n bits.
func GetGroup(n int) (*Group, error) {
	group, ok := rfcGroups[n]
	if !ok {
		return nil, util.ErrGroupNotFound
	}

	return group, nil
}
