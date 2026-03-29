package srp_test

import (
	"crypto"
	"errors"
	"math/big"
	"testing"

	"github.com/bodgit/srp"
	"github.com/bodgit/srp/internal/rfc5054"
	"github.com/bodgit/srp/internal/util"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newSRP() *srp.SRP {
	return util.Must(srp.NewSRP(crypto.SHA1, util.Must(srp.GetGroup(1024))))
}

func TestNewSRP(t *testing.T) {
	t.Parallel()

	s, err := srp.NewSRP(crypto.SHA1, util.Must(srp.GetGroup(1024)), srp.K(func(*srp.SRP) *big.Int {
		return new(big.Int)
	}), srp.X(func(*srp.SRP, []byte, []byte, []byte) *big.Int {
		return new(big.Int)
	}))

	assert.NotNil(t, s)
	require.NoError(t, err)

	errTest := errors.New("test") //nolint:err113

	s, err = srp.NewSRP(crypto.SHA1, util.Must(srp.GetGroup(1024)), func(*srp.SRP) error {
		return errTest
	})

	assert.Nil(t, s)
	assert.Equal(t, errTest, err)
}

func TestNewISV(t *testing.T) {
	t.Parallel()

	s := newSRP()
	i := util.Must(s.NewISV(rfc5054.Identity, rfc5054.Password))

	assert.Len(t, i.Identity, len(rfc5054.Identity))
	assert.Len(t, i.Salt, s.Group().Size)
	assert.Len(t, i.Verifier, s.Group().Size)
}

func TestNewClient(t *testing.T) {
	t.Parallel()

	s := newSRP()
	client := util.Must(s.NewClient(rfc5054.Identity, rfc5054.Password))

	assert.Len(t, client.A(), s.Group().Size)
}

func TestNewServer(t *testing.T) {
	t.Parallel()

	s := newSRP()
	server := util.Must(s.NewServer(util.Must(s.NewISV(rfc5054.Identity, rfc5054.Password)), rfc5054.XA))

	assert.Len(t, server.B(), s.Group().Size)
}

func TestHandshake(t *testing.T) {
	t.Parallel()

	g, err := srp.GetGroup(8192)
	if err != nil {
		t.Fatal(err)
	}

	s, err := srp.NewSRP(crypto.SHA256, g)
	if err != nil {
		t.Fatal(err)
	}

	client, err := s.NewClient(rfc5054.Identity, rfc5054.Password)
	if err != nil {
		t.Fatal(err)
	}

	i, err := s.NewISV(rfc5054.Identity, rfc5054.Password)
	if err != nil {
		t.Fatal(err)
	}

	server, err := s.NewServer(i, client.A())
	if err != nil {
		t.Fatal(err)
	}

	m1, err := client.Compute(server.Salt(), server.B())
	if err != nil {
		t.Fatal(err)
	}

	m2, err := server.Check(m1)
	if err != nil {
		t.Fatal(err)
	}

	if err := client.Check(m2); err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, client.Key(), server.Key())
}
