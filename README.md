[![GitHub release](https://img.shields.io/github/v/release/bodgit/srp)](https://github.com/bodgit/srp/releases)
[![Build Status](https://img.shields.io/github/actions/workflow/status/bodgit/srp/main.yml?branch=main)](https://github.com/bodgit/srp/actions?query=workflow%3Abuild)
[![Coverage Status](https://coveralls.io/repos/github/bodgit/srp/badge.svg?branch=main)](https://coveralls.io/github/bodgit/srp?branch=main)
[![Go Report Card](https://goreportcard.com/badge/github.com/bodgit/srp)](https://goreportcard.com/report/github.com/bodgit/srp)
[![GoDoc](https://godoc.org/github.com/bodgit/srp?status.svg)](https://godoc.org/github.com/bodgit/srp)
![Go version](https://img.shields.io/badge/Go-1.19-brightgreen.svg)
![Go version](https://img.shields.io/badge/Go-1.18-brightgreen.svg)

# SRP

An implementation of SRP-6a as documented in [RFC 5054](https://www.rfc-editor.org/rfc/rfc5054) and [RFC 2945](https://www.rfc-editor.org/rfc/rfc2945). It also exports modified versions of routines allowing it to be used with [AWS Cognito](https://aws.amazon.com/cognito/) which uses a variation of SRP.

Generate the verifier:
```golang
package main

import "github.com/bodgit/srp"

func main() {
	g, err := srp.GetGroup(1024)
	if err != nil {
		panic(err)
	}

	s, err := srp.NewSRP(crypto.SHA1, g)
	if err != nil {
		panic(err)
	}

	i, err := s.NewISV("username", "password")
	if err != nil {
		panic(err)
	}

	// Marshal and store i on the server against the identity
}
```

Example client:
```golang
package main

import "github.com/bodgit/srp"

func main() {
	g, err := srp.GetGroup(1024)
	if err != nil {
		panic(err)
	}

	s, err := srp.NewSRP(crypto.SHA1, g)
	if err != nil {
		panic(err)
	}

	client, err := s.NewClient("username", "password")
	if err != nil {
		panic(err)
	}

	// Send identity and client.A() to the server, receive salt and B

	m1, err := client.Compute(salt, b)
	if err != nil {
		panic(err)
	}

	// Send m1 to the server, receive m2

	if err := client.Check(m2); err != nil {
		panic(err)
	}

	// Use client.Key()
}
```

Example server:
```golang
package main

import "github.com/bodgit/srp"

func main() {
	g, err := srp.GetGroup(1024)
	if err != nil {
		panic(err)
	}

	s, err := srp.NewSRP(crypto.SHA1, g)
	if err != nil {
		panic(err)
	}

	// Receive identity and A from client, lookup/unmarshal ISV i

	server, err := s.NewServer(i, a)
	if err != nil {
		panic(err)
	}

	// Send server.Salt() and server.B() to the client, receive m1

	m2, err := server.Check(m1)
	if err != nil {
		panic(err)
	}

	// Send m2 to the client, use server.Key()
}
```
## Other implementations

* [https://github.com/opencoff/go-srp](https://github.com/opencoff/go-srp) - Calculates verifier value differently compared to RFC so session keys never match
* [https://github.com/Kong/go-srp](https://github.com/Kong/go-srp) - Calculates proof values differently compared to RFC but session keys match
* [https://github.com/posterity/srp](https://github.com/posterity/srp) - Interoperates fine

The last two implementations however assume that the client knows their salt value from the start rather than waiting for the server to provide it which doesn't match the behaviour documented in the RFC.
