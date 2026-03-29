// Package rfc2945 provides test vectors documented in
// RFC 2945.
//
//nolint:gochecknoglobals
package rfc2945

import "github.com/bodgit/srp/internal/util"

// RFC 2945 SRP Test Vectors.
var (
	M1 = util.Must(util.BytesFromHexString(`
		3F3BC671 69EA7130 2599CF1B 0F5D408B 7B65D347`))
	M2 = util.Must(util.BytesFromHexString(`
		9CAB3C57 5A11DE37 D3AC1421 A9F00923 6A48EB55`))
)
