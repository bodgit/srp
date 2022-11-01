package cognito_test

import (
	"math/big"
	"testing"

	"github.com/bodgit/srp/cognito"
	"github.com/bodgit/srp/internal/rfc5054"
	"github.com/bodgit/srp/internal/util"
	"github.com/stretchr/testify/assert"
)

func TestGetGroup(t *testing.T) {
	t.Parallel()

	tables := []struct {
		group int
		err   error
	}{
		{
			3072,
			nil,
		},
		{
			23,
			util.ErrGroupNotFound,
		},
	}

	for _, table := range tables {
		_, err := cognito.GetGroup(table.group)

		if table.err != nil && assert.Error(t, err) {
			assert.ErrorIs(t, err, table.err)
		}
	}
}

func TestMultiplier(t *testing.T) {
	t.Parallel()

	s := util.Must(cognito.NewSRP())
	k := util.Must(util.BytesFromHexString(`
		538282C4 354742D7 CBBDE235 9FCF67F9 F5B3A6B0 8791E501 1B43B8A5
		B66D9EE6`))

	assert.Equal(t, k, cognito.Multiplier(s).Bytes())
}

func TestComputeX(t *testing.T) {
	t.Parallel()

	s := util.Must(cognito.NewSRP())
	x := util.Must(util.BytesFromHexString(`
		97F91DB8 61D41612 200F60FD CDF7E6F2 C4671020 9EFC5103 AD6B2092
		ACDD210B`))

	assert.Equal(t, x, cognito.ComputeX(s, rfc5054.Identity, rfc5054.Password, rfc5054.Salt).Bytes())
}

func TestComputeU(t *testing.T) {
	t.Parallel()

	s := util.Must(cognito.NewSRP())
	u := util.Must(util.BytesFromHexString(`
		A51B9791 F47003ED 17017E2D 5D57E98D 8EF603E6 992EB4A7 655B3F21
		5134BC5D`))

	assert.Equal(t, u, cognito.ComputeU(s, new(big.Int).SetBytes(rfc5054.XA), new(big.Int).SetBytes(rfc5054.XB)).Bytes())
}
