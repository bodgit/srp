package srp

import (
	"crypto/subtle"
	"errors"
	"math/big"
)

// Client represents the client-side of an SRP session.
type Client struct {
	s                        *SRP
	identity, password, salt []byte
	a, xA, xB, xS, u         *big.Int
	m1, m2                   []byte
}

var errClientNotReady = errors.New("set the server public key first")

// A returns the client public value.
func (c *Client) A() []byte {
	return c.xA.Bytes()
}

// SetIdentity sets the client identity.
func (c *Client) SetIdentity(identity []byte) {
	c.identity = identity
}

// Compute takes the salt and public value provided by the server and computes
// the proofs and shared key. It returns the M1 proof to be sent to the server.
func (c *Client) Compute(salt, xB []byte) ([]byte, error) {
	b := new(big.Int).SetBytes(xB)
	if new(big.Int).Mod(b, c.s.Group().N).Sign() == 0 {
		return nil, ErrInvalidPublicKey
	}

	c.xB, c.salt = b, salt

	var err error

	c.u, err = c.s.computeU(c.xA, c.xB)
	if err != nil {
		return nil, err
	}

	c.xS = c.s.computeClientS(c.a, c.xB, c.s.multiplier(), c.u, c.s.computeX(c.identity, c.password, c.salt))
	c.m1 = c.s.computeM1(c.xA, c.xB, c.s.computeK(c.xS), c.identity, c.salt)
	c.m2 = c.s.computeM2(c.xA, c.m1, c.s.computeK(c.xS))

	return c.m1, nil
}

// S returns the computed S value after c.Compute() has been called, otherwise
// an error is returned.
func (c *Client) S() ([]byte, error) {
	if c.xS == nil {
		return nil, errClientNotReady
	}

	return c.xS.Bytes(), nil
}

// U returns the computed U value after c.Compute() has been called, otherwise
// an error is returned.
func (c *Client) U() ([]byte, error) {
	if c.u == nil {
		return nil, errClientNotReady
	}

	return c.u.Bytes(), nil
}

// Check compares the M2 proof computed by the server with the clients copy.
func (c *Client) Check(m2 []byte) error {
	if subtle.ConstantTimeCompare(m2, c.m2) != 1 {
		return errMismatchedProof
	}

	return nil
}

// Key returns the key shared with the server.
func (c *Client) Key() []byte {
	return c.s.computeK(c.xS)
}
