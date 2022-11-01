// Package rfc5054 provides the prime numbers and test vectors documented in
// RFC 5054.
package rfc5054

import (
	_ "embed" // embed
)

var (
	// Hex1024 is the 1024-bit prime
	//go:embed prime/1024.txt
	Hex1024 string

	// Hex1536 is the 1536-bit prime
	//go:embed prime/1536.txt
	Hex1536 string

	// Hex2048 is the 2048-bit prime
	//go:embed prime/2048.txt
	Hex2048 string

	// Hex3072 is the 3072-bit prime
	//go:embed prime/3072.txt
	Hex3072 string

	// Hex4096 is the 4096-bit prime
	//go:embed prime/4096.txt
	Hex4096 string

	// Hex6144 is the 6144-bit prime
	//go:embed prime/6144.txt
	Hex6144 string

	// Hex8192 is the 8192-bit prime
	//go:embed prime/8192.txt
	Hex8192 string
)
