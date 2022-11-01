package srp_test

import (
	"testing"

	"github.com/bodgit/srp"
	"github.com/bodgit/srp/internal/rfc5054"
	"github.com/stretchr/testify/assert"
)

func TestServer_MarshalBinary(t *testing.T) {
	t.Parallel()

	s := newSRP()

	i, err := s.NewISV(rfc5054.Identity, rfc5054.Password)
	if err != nil {
		t.Fatal(err)
	}

	server, err := s.NewServer(i, rfc5054.XA)
	if err != nil {
		t.Fatal(err)
	}

	b, err := server.MarshalBinary()

	assert.NotNil(t, b)
	assert.Nil(t, err)
}

func TestServer_UnmarshalBinary(t *testing.T) {
	t.Parallel()

	s := newSRP()

	i, err := s.NewISV(rfc5054.Identity, rfc5054.Password)
	if err != nil {
		t.Fatal(err)
	}

	server, err := s.NewServer(i, rfc5054.XA)
	if err != nil {
		t.Fatal(err)
	}

	b, err := server.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}

	newServer := new(srp.Server)
	if err := newServer.UnmarshalBinary(b); err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, server, newServer)
}
