package srp

import (
	"crypto"
	"errors"
	"fmt"
	"math"
	"math/big"

	"github.com/bodgit/srp/internal/util"
)

// SRP manages the various computations used in the SRP protocol.
type SRP struct {
	h crypto.Hash
	g *Group

	x func(*SRP, []byte, []byte, []byte) *big.Int
	k func(*SRP) *big.Int
	u func(*SRP, *big.Int, *big.Int) *big.Int
}

var (
	// ErrInvalidPublicKey means the public key is invalid.
	ErrInvalidPublicKey = errors.New("invalid public key")

	// ErrTrailingBytes means there were additional trailing bytes when
	// unmarshalling.
	ErrTrailingBytes = errors.New("trailing bytes")

	// ErrTooBig means the length of the value exceeds the size of a 16-bit
	// integer.
	ErrTooBig = fmt.Errorf("value exceeds %d bytes", math.MaxUint16)

	errMismatchedProof = errors.New("mismatched proof")
)

// NewSRP returns a new SRP using the chosen hash and group along with any
// options.
func NewSRP(hash crypto.Hash, group *Group, options ...func(*SRP) error) (*SRP, error) {
	s := &SRP{
		h: hash,
		g: group,
	}

	if err := s.setOption(options...); err != nil {
		return nil, err
	}

	return s, nil
}

func (s *SRP) setOption(options ...func(*SRP) error) error {
	for _, option := range options {
		if err := option(s); err != nil {
			return err
		}
	}

	return nil
}

// K overrides the default function for computing the multiplier.
func K(f func(*SRP) *big.Int) func(*SRP) error {
	return func(s *SRP) error {
		s.k = f

		return nil
	}
}

// SetK overrides the default function for computing the multiplier.
func (s *SRP) SetK(f func(*SRP) *big.Int) error {
	return s.setOption(K(f))
}

// X overrides the default function for computing the X value.
func X(f func(*SRP, []byte, []byte, []byte) *big.Int) func(*SRP) error {
	return func(s *SRP) error {
		s.x = f

		return nil
	}
}

// SetX overrides the default function for computing the X value.
func (s *SRP) SetX(f func(*SRP, []byte, []byte, []byte) *big.Int) error {
	return s.setOption(X(f))
}

// U overrides the default function for computing the U value.
func U(f func(*SRP, *big.Int, *big.Int) *big.Int) func(*SRP) error {
	return func(s *SRP) error {
		s.u = f

		return nil
	}
}

// SetU overrides the default function for computing the U value.
func (s *SRP) SetU(f func(*SRP, *big.Int, *big.Int) *big.Int) error {
	return s.setOption(U(f))
}

// Group returns the Group in use.
func (s *SRP) Group() *Group {
	return s.g
}

func (s *SRP) multiplier() *big.Int {
	if s.k != nil {
		return s.k(s)
	}

	return s.HashInt(s.Group().N.Bytes(), util.Pad(s.Group().G, s.Group().Size))
}

func (s *SRP) computeA(a *big.Int) *big.Int {
	return new(big.Int).Exp(s.Group().G, a, s.Group().N)
}

func (s *SRP) computeB(b, k, v *big.Int) *big.Int {
	// B = k*v + g^b % N
	return new(big.Int).Mod(
		new(big.Int).Add(
			new(big.Int).Mul(k, v),
			new(big.Int).Exp(s.Group().G, b, s.Group().N)),
		s.Group().N)
}

func (s *SRP) computeX(identity, password, salt []byte) *big.Int {
	if s.x != nil {
		return s.x(s, identity, password, salt)
	}

	// x = H(s | H(I | ":" | P))
	return s.HashInt(salt, s.HashBytes(identity, []byte(":"), password))
}

func (s *SRP) computeV(x *big.Int) *big.Int {
	return new(big.Int).Exp(s.Group().G, x, s.Group().N)
}

func (s *SRP) computeU(xA, xB *big.Int) (*big.Int, error) {
	var u *big.Int

	if s.u != nil {
		u = s.u(s, xA, xB)
	} else {
		// u = H(A | B)
		u = s.HashInt(util.Pad(xA, s.Group().Size), util.Pad(xB, s.Group().Size))
	}

	if u.Sign() == 0 {
		return nil, ErrInvalidPublicKey
	}

	return u, nil
}

func (s *SRP) computeClientS(a, xB, k, u, x *big.Int) *big.Int {
	// S = ((B - kg^x) ^ (a + ux)) % N
	return new(big.Int).Exp(
		new(big.Int).Sub(xB, new(big.Int).Mul(k, new(big.Int).Exp(s.Group().G, x, s.Group().N))),
		new(big.Int).Add(a, new(big.Int).Mul(u, x)),
		s.Group().N)
}

func (s *SRP) computeServerS(xA, b, u, v *big.Int) *big.Int {
	// S = ((Av^u) ^ b) % N
	return new(big.Int).Exp(new(big.Int).Mul(xA, new(big.Int).Exp(v, u, s.Group().N)), b, s.Group().N)
}

func (s *SRP) computeK(xS *big.Int) []byte {
	return s.HashBytes(xS.Bytes())
}

func (s *SRP) computeM1(xA, xB *big.Int, xK, identity, salt []byte) []byte {
	// M1 = H(H(N) XOR H(g) | H(U) | s | A | B | K)
	xor := make([]byte, s.h.New().Size())
	_ = xorBytes(xor, s.HashBytes(s.Group().N.Bytes()), s.HashBytes(s.Group().G.Bytes()))

	return s.HashBytes(xor, s.HashBytes(identity), salt, xA.Bytes(), xB.Bytes(), xK)
}

func (s *SRP) computeM2(xA *big.Int, m1, xK []byte) []byte {
	// M2 = H(A | M | K)
	return s.HashBytes(xA.Bytes(), m1, xK)
}

// HashBytes hashes each passed byte slice and returns the digest.
func (s *SRP) HashBytes(a ...[]byte) []byte {
	h := s.h.New()

	for _, z := range a {
		_, _ = h.Write(z)
	}

	return h.Sum(nil)
}

// HashInt hashes each passed byte slice and returns the digest as a big.Int.
func (s *SRP) HashInt(a ...[]byte) *big.Int {
	return new(big.Int).SetBytes(s.HashBytes(a...))
}

// NewISV creates a new ISV containing the identity, salt and verifier.
func (s *SRP) NewISV(identity, password []byte) (*ISV, error) {
	salt, err := randBytes(s.Group().Size)
	if err != nil {
		return nil, err
	}

	return &ISV{
		Identity: identity,
		Salt:     salt,
		Verifier: s.computeV(s.computeX(identity, password, salt)).Bytes(),
	}, nil
}

// NewClient creates a new Client using the identity and password.
func (s *SRP) NewClient(identity, password []byte) (*Client, error) {
	a, err := randBigInt(s.Group().Size)
	if err != nil {
		return nil, err
	}

	return &Client{
		s:        s,
		identity: identity,
		password: password,
		a:        a,
		xA:       s.computeA(a),
	}, nil
}

// NewServer creates a new Server using the ISV and the client public value.
func (s *SRP) NewServer(i *ISV, xA []byte) (*Server, error) {
	server := new(Server)

	return server, server.Reset(s, i, xA)
}
