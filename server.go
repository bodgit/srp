package srp

import (
	"bytes"
	"crypto/subtle"
	"io"
	"math/big"
)

// Server represents the server-side of an SRP session. It implements
// encoding.BinaryMarshaler and encoding.BinaryUnmarshaler so it can be
// serialized to and from persistent storage.
type Server struct {
	xA, b, xB, xS    *big.Int
	salt, xK, m1, m2 []byte
}

// Reset resets s to its initial state using the passed parameters.
func (s *Server) Reset(srp *SRP, i *ISV, xA []byte) error {
	a := new(big.Int).SetBytes(xA)
	if new(big.Int).Mod(a, srp.Group().N).Sign() == 0 {
		return ErrInvalidPublicKey
	}

	b, err := randBigInt(srp.Group().Size)
	if err != nil {
		return err
	}

	v := new(big.Int).SetBytes(i.Verifier)

	s.xA = a
	s.b, s.xB = b, srp.computeB(b, srp.multiplier(), v)
	s.salt = i.Salt

	u, err := srp.computeU(s.xA, s.xB)
	if err != nil {
		return err
	}

	s.xS = srp.computeServerS(s.xA, s.b, u, v)
	s.xK = srp.computeK(s.xS)
	s.m1 = srp.computeM1(s.xA, s.xB, s.xK, i.Identity, s.salt)
	s.m2 = srp.computeM2(s.xA, s.m1, s.xK)

	return nil
}

// Salt returns the client salt value.
func (s *Server) Salt() []byte {
	return s.salt
}

// B returns the server public value.
func (s *Server) B() []byte {
	return s.xB.Bytes()
}

// Check compares the M1 proof computed by the client with the servers copy.
// If it is identical then the servers M2 proof is returned to be sent back to
// the client.
func (s *Server) Check(m1 []byte) ([]byte, error) {
	if subtle.ConstantTimeCompare(m1, s.m1) != 1 {
		return nil, errMismatchedProof
	}

	return s.m2, nil
}

// Key returns the key shared with the client.
func (s *Server) Key() []byte {
	return s.xK
}

// MarshalBinary satisfies the encoding.BinaryMarshaler interface.
func (s *Server) MarshalBinary() ([]byte, error) {
	b := new(bytes.Buffer)

	if err := writeBytes(b, s.xA.Bytes()); err != nil {
		return nil, err
	}

	if err := writeBytes(b, s.b.Bytes()); err != nil {
		return nil, err
	}

	if err := writeBytes(b, s.xB.Bytes()); err != nil {
		return nil, err
	}

	if err := writeBytes(b, s.xS.Bytes()); err != nil {
		return nil, err
	}

	if err := writeBytes(b, s.salt); err != nil {
		return nil, err
	}

	if err := writeBytes(b, s.xK); err != nil {
		return nil, err
	}

	if err := writeBytes(b, s.m1); err != nil {
		return nil, err
	}

	if err := writeBytes(b, s.m2); err != nil {
		return nil, err
	}

	return b.Bytes(), nil
}

// UnmarshalBinary satisfies the encoding.BinaryUnmarshaler interface.
func (s *Server) UnmarshalBinary(b []byte) error {
	r := bytes.NewReader(b)

	xA, err := readBytes(r)
	if err != nil {
		return err
	}

	s.xA = new(big.Int).SetBytes(xA)

	bb, err := readBytes(r)
	if err != nil {
		return err
	}

	s.b = new(big.Int).SetBytes(bb)

	xB, err := readBytes(r)
	if err != nil {
		return err
	}

	s.xB = new(big.Int).SetBytes(xB)

	xS, err := readBytes(r)
	if err != nil {
		return err
	}

	s.xS = new(big.Int).SetBytes(xS)

	if s.salt, err = readBytes(r); err != nil {
		return err
	}

	if s.xK, err = readBytes(r); err != nil {
		return err
	}

	if s.m1, err = readBytes(r); err != nil {
		return err
	}

	if s.m2, err = readBytes(r); err != nil {
		return err
	}

	if n, _ := io.CopyN(io.Discard, r, 1); n > 0 {
		return ErrTrailingBytes
	}

	return nil
}
