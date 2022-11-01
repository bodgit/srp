// Package cognito contains the SRP primitives that differ between RFC 5054
// and the AWS Cognito implementation.
package cognito

import (
	"crypto"
	"math/big"

	"github.com/bodgit/srp"
	"github.com/bodgit/srp/internal/rfc5054"
	"github.com/bodgit/srp/internal/util"
)

var cognitoGroups = map[int]*srp.Group{
	3072: util.Must(srp.NewGroup(2, 3072, rfc5054.Hex3072)), //nolint:gomnd
}

// GetGroup returns the AWS Cognito group for the prime of n bits.
func GetGroup(n int) (*srp.Group, error) {
	group, ok := cognitoGroups[n]
	if !ok {
		return nil, util.ErrGroupNotFound
	}

	return group, nil
}

// NewSRP returns a new srp.SRP struct with the Cognito-specific options
// already set.
func NewSRP() (*srp.SRP, error) {
	//nolint:gomnd,wrapcheck
	return srp.NewSRP(crypto.SHA256, util.Must(GetGroup(3072)), srp.K(Multiplier), srp.U(ComputeU), srp.X(ComputeX))
}

// Pad prepends a zero byte to slice b if the first byte is greater than or
// equal to 0x80.
func Pad(b []byte) []byte {
	if b[0] >= 0x80 { //nolint:gomnd
		b = append([]byte{0x00}, b...)
	}

	return b
}

// Multiplier calculates the SRP multiplier K according to the AWS Cognito
// implementation.
func Multiplier(s *srp.SRP) *big.Int {
	return s.HashInt(Pad(s.Group().N.Bytes()), s.Group().G.Bytes())
}

// ComputeU calculates the SRP hash of both public A and B values according to
// the AWS Cognito implementation.
func ComputeU(s *srp.SRP, xA, xB *big.Int) *big.Int {
	return s.HashInt(Pad(xA.Bytes()), Pad(xB.Bytes()))
}

// ComputeX calculates the SRP hash of the identity/username, password
// according to the AWS Cognito implementation.
func ComputeX(s *srp.SRP, identity, password, salt []byte) *big.Int {
	return s.HashInt(Pad(salt), s.HashBytes(identity, []byte(":"), password))
}
