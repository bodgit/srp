package srp

import (
	"bytes"
	"io"
)

// ISV holds the triplet of the Identity, Salt, and Verifier. It implements
// encoding.BinaryMarshaler and encoding.BinaryUnmarshaler so it can be
// serialized to and from persistent storage.
type ISV struct {
	Identity []byte `json:"identity"`
	Salt     []byte `json:"salt"`
	Verifier []byte `json:"verifier"`
}

// MarshalBinary satisfies the encoding.BinaryMarshaler interface.
func (i *ISV) MarshalBinary() ([]byte, error) {
	b := new(bytes.Buffer)

	if err := writeBytes(b, i.Identity); err != nil {
		return nil, err
	}

	if err := writeBytes(b, i.Salt); err != nil {
		return nil, err
	}

	if err := writeBytes(b, i.Verifier); err != nil {
		return nil, err
	}

	return b.Bytes(), nil
}

// UnmarshalBinary satisfies the encoding.BinaryUnmarshaler interface.
func (i *ISV) UnmarshalBinary(b []byte) (err error) {
	r := bytes.NewReader(b)

	if i.Identity, err = readBytes(r); err != nil {
		return
	}

	if i.Salt, err = readBytes(r); err != nil {
		return
	}

	if i.Verifier, err = readBytes(r); err != nil {
		return
	}

	if n, _ := io.CopyN(io.Discard, r, 1); n > 0 {
		return ErrTrailingBytes
	}

	return nil
}
