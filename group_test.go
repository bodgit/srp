package srp_test

import (
	"encoding/hex"
	"testing"

	"github.com/bodgit/srp"
	"github.com/bodgit/srp/internal/rfc5054"
	"github.com/bodgit/srp/internal/util"
	"github.com/stretchr/testify/assert"
)

func TestNewGroup(t *testing.T) {
	t.Parallel()

	tables := []struct {
		g    int64
		size int
		s    string
		err  error
	}{
		{
			2,
			1024,
			rfc5054.Hex1024,
			nil,
		},
		{
			2,
			1024,
			"0",
			hex.ErrLength,
		},
	}

	for _, table := range tables {
		_, err := srp.NewGroup(table.g, table.size, table.s)

		assert.ErrorIs(t, err, table.err)
	}
}

func TestGetGroup(t *testing.T) {
	t.Parallel()

	tables := []struct {
		group int
		err   error
	}{
		{
			1024,
			nil,
		},
		{
			1536,
			nil,
		},
		{
			2048,
			nil,
		},
		{
			3072,
			nil,
		},
		{
			4096,
			nil,
		},
		{
			6144,
			nil,
		},
		{
			8192,
			nil,
		},
		{
			23,
			util.ErrGroupNotFound,
		},
	}

	for _, table := range tables {
		_, err := srp.GetGroup(table.group)

		if table.err != nil && assert.Error(t, err) {
			assert.ErrorIs(t, err, table.err)
		}
	}
}
