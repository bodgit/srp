package srp

import (
	"crypto"
	"math/big"
	"testing"

	"github.com/bodgit/srp/internal/rfc5054"
	"github.com/bodgit/srp/internal/util"
	"github.com/stretchr/testify/assert"
)

func newSRP() *SRP {
	return util.Must(NewSRP(crypto.SHA1, util.Must(GetGroup(1024))))
}

func TestSRP_multiplier(t *testing.T) {
	t.Parallel()

	tables := []struct {
		hash       crypto.Hash
		group      *Group
		multiplier func(*SRP) *big.Int
		want       []byte
	}{
		{
			crypto.SHA1,
			util.Must(GetGroup(1024)),
			nil,
			rfc5054.K,
		},
		{
			crypto.SHA1,
			util.Must(GetGroup(1024)),
			func(*SRP) *big.Int {
				return big.NewInt(1)
			},
			[]byte{0x01},
		},
	}

	for _, table := range tables {
		s := util.Must(NewSRP(table.hash, table.group))

		if table.multiplier != nil {
			_ = s.SetK(table.multiplier)
		}

		assert.Equal(t, table.want, s.multiplier().Bytes())
	}
}

func TestSRP_computeX(t *testing.T) {
	t.Parallel()

	tables := []struct {
		hash                     crypto.Hash
		group                    *Group
		kdf                      func(*SRP, []byte, []byte, []byte) *big.Int
		identity, password, salt []byte
		want                     []byte
	}{
		{
			crypto.SHA1,
			util.Must(GetGroup(1024)),
			nil,
			rfc5054.Identity,
			rfc5054.Password,
			rfc5054.Salt,
			rfc5054.X,
		},
		{
			crypto.SHA1,
			util.Must(GetGroup(1024)),
			func(*SRP, []byte, []byte, []byte) *big.Int {
				return big.NewInt(1)
			},
			rfc5054.Identity,
			rfc5054.Password,
			rfc5054.Salt,
			[]byte{0x01},
		},
	}

	for _, table := range tables {
		s := util.Must(NewSRP(table.hash, table.group))

		if table.kdf != nil {
			_ = s.SetX(table.kdf)
		}

		assert.Equal(t, table.want, s.computeX(table.identity, table.password, table.salt).Bytes())
	}
}

func TestSRP_computeV(t *testing.T) {
	t.Parallel()

	assert.Equal(t, rfc5054.V, newSRP().computeV(new(big.Int).SetBytes(rfc5054.X)).Bytes())
}

func TestSRP_computeA(t *testing.T) {
	t.Parallel()

	assert.Equal(t, rfc5054.XA, newSRP().computeA(new(big.Int).SetBytes(rfc5054.A)).Bytes())
}

func TestSRP_computeB(t *testing.T) {
	t.Parallel()

	assert.Equal(t, rfc5054.XB, newSRP().computeB(
		new(big.Int).SetBytes(rfc5054.B),
		new(big.Int).SetBytes(rfc5054.K),
		new(big.Int).SetBytes(rfc5054.V)).Bytes())
}

func TestSRP_computeU(t *testing.T) {
	t.Parallel()

	u, err := newSRP().computeU(new(big.Int).SetBytes(rfc5054.XA), new(big.Int).SetBytes(rfc5054.XB))
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, rfc5054.U, u.Bytes())
}

func TestSRP_computeClientS(t *testing.T) {
	t.Parallel()

	assert.Equal(t, rfc5054.PremasterSecret, newSRP().computeClientS(
		new(big.Int).SetBytes(rfc5054.A),
		new(big.Int).SetBytes(rfc5054.XB),
		new(big.Int).SetBytes(rfc5054.K),
		new(big.Int).SetBytes(rfc5054.U),
		new(big.Int).SetBytes(rfc5054.X)).Bytes())
}

func TestSRP_computeServerS(t *testing.T) {
	t.Parallel()

	assert.Equal(t, rfc5054.PremasterSecret, newSRP().computeServerS(
		new(big.Int).SetBytes(rfc5054.XA),
		new(big.Int).SetBytes(rfc5054.B),
		new(big.Int).SetBytes(rfc5054.U),
		new(big.Int).SetBytes(rfc5054.V)).Bytes())
}
