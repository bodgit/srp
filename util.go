package srp

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"math"
	"math/big"
)

func randBytes(n int) ([]byte, error) {
	b := make([]byte, n)

	_, err := io.ReadFull(rand.Reader, b)
	if err != nil {
		return nil, fmt.Errorf("unable to read random bytes: %w", err)
	}

	return b, nil
}

func randBigInt(n int) (*big.Int, error) {
	b, err := randBytes(n)
	if err != nil {
		return nil, err
	}

	return new(big.Int).SetBytes(b), nil
}

func writeBytes(w io.Writer, b []byte) error {
	if len(b) > math.MaxUint16 {
		return ErrTooBig
	}

	if err := binary.Write(w, binary.BigEndian, uint16(len(b))); err != nil {
		return fmt.Errorf("unable to write length: %w", err)
	}

	if _, err := w.Write(b); err != nil {
		return fmt.Errorf("unable t write bytes: %w", err)
	}

	return nil
}

func readBytes(r io.Reader) ([]byte, error) {
	var length uint16
	if err := binary.Read(r, binary.BigEndian, &length); err != nil {
		return nil, fmt.Errorf("unable to read length: %w", err)
	}

	b := make([]byte, length)
	if _, err := io.ReadFull(r, b); err != nil {
		return nil, fmt.Errorf("unable to read bytes: %w", err)
	}

	return b, nil
}
