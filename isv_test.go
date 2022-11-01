package srp_test

import (
	"io"
	"math"
	"testing"

	"github.com/bodgit/srp"
	"github.com/stretchr/testify/assert"
)

var isv = []byte{0x00, 0x01, 0x01, 0x00, 0x01, 0x02, 0x00, 0x01, 0x03}

func TestISV_MarshalBinary(t *testing.T) {
	t.Parallel()

	tables := []struct {
		identity, salt, verifier []byte
		b                        []byte
		err                      error
	}{
		{
			make([]byte, math.MaxUint16+1),
			[]byte{0x00},
			[]byte{0x00},
			nil,
			srp.ErrTooBig,
		},
		{
			[]byte{0x00},
			make([]byte, math.MaxUint16+1),
			[]byte{0x00},
			nil,
			srp.ErrTooBig,
		},
		{
			[]byte{0x00},
			[]byte{0x00},
			make([]byte, math.MaxUint16+1),
			nil,
			srp.ErrTooBig,
		},
		{
			[]byte{0x01},
			[]byte{0x02},
			[]byte{0x03},
			isv,
			nil,
		},
	}

	for _, table := range tables {
		i := &srp.ISV{
			Identity: table.identity,
			Salt:     table.salt,
			Verifier: table.verifier,
		}

		b, err := i.MarshalBinary()

		assert.Equal(t, table.b, b)
		assert.ErrorIs(t, err, table.err)
	}
}

//nolint:funlen
func TestISV_UnmarshalBinary(t *testing.T) {
	t.Parallel()

	tables := []struct {
		b                        []byte
		err                      error
		identity, salt, verifier []byte
	}{
		{
			isv[:1],
			io.ErrUnexpectedEOF,
			nil,
			nil,
			nil,
		},
		{
			isv[:2],
			io.EOF,
			nil,
			nil,
			nil,
		},
		{
			isv[:4],
			io.ErrUnexpectedEOF,
			nil,
			nil,
			nil,
		},
		{
			isv[:5],
			io.EOF,
			nil,
			nil,
			nil,
		},
		{
			isv[:7],
			io.ErrUnexpectedEOF,
			nil,
			nil,
			nil,
		},
		{
			isv[:8],
			io.EOF,
			nil,
			nil,
			nil,
		},
		{
			append(isv, 0x00),
			srp.ErrTrailingBytes,
			nil,
			nil,
			nil,
		},
		{
			isv,
			nil,
			[]byte{0x01},
			[]byte{0x02},
			[]byte{0x03},
		},
	}

	for _, table := range tables {
		i := new(srp.ISV)

		err := i.UnmarshalBinary(table.b)

		assert.ErrorIs(t, err, table.err)

		if err == nil {
			assert.Equal(t, table.identity, i.Identity)
			assert.Equal(t, table.salt, i.Salt)
			assert.Equal(t, table.verifier, i.Verifier)
		}
	}
}
