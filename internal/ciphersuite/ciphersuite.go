// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

// Package ciphersuite provides the built-in DTLS 1.3 cipher suites.
package ciphersuite

import (
	"crypto/sha256"
	"crypto/sha512"
	"hash"
	"math"

	cryptosuite "github.com/pion/dtls/v4/internal/crypto/ciphersuite"
)

func ForID(id cryptosuite.ID) cryptosuite.Suite { return builtinCipherSuites[id] }

type suiteMetadata struct {
	id       cryptosuite.ID
	hashFunc func() hash.Hash
}

func (s suiteMetadata) String() string             { return s.id.String() }
func (s suiteMetadata) ID() cryptosuite.ID         { return s.id }
func (s suiteMetadata) HashFunc() func() hash.Hash { return s.hashFunc }

type protectionAlgorithm13 uint8

const (
	protection13AESGCM protectionAlgorithm13 = iota + 1
	protection13ChaCha20Poly1305
)

type suite13 struct {
	suiteMetadata
	algorithm protectionAlgorithm13
	keyLen    int
}

func newSuite13(
	id cryptosuite.ID,
	hashFunc func() hash.Hash,
	algorithm protectionAlgorithm13,
	keyLen int,
) *suite13 {
	return &suite13{suiteMetadata: suiteMetadata{id: id, hashFunc: hashFunc}, algorithm: algorithm, keyLen: keyLen}
}

// UsageLimits reports advisory AEAD recommendations for DTLS 1.3.
// AES-GCM, DTLS 1.3 is limited to 23,726,566 successful encryptions and 2^36 authentication failures.
// ChaCha20-Poly1305 is limited to MaxUint64 successful encryptions (record-number limit) and 2^36 authentication failures.
//
// DTLS 1.3 AEAD limits: https://www.rfc-editor.org/rfc/rfc9147.html#section-4.5.3
// ChaCha20 limits adopted from DTLS 1.3: https://www.rfc-editor.org/rfc/rfc9147.html#section-4.5.3
// Encryption bounds: https://www.rfc-editor.org/rfc/rfc8446.html#section-5.5
func (s *suite13) UsageLimits() cryptosuite.UsageLimits {
	maxSealed := uint64(23726566)
	if s.algorithm == protection13ChaCha20Poly1305 {
		maxSealed = math.MaxUint64
	}

	return cryptosuite.UsageLimits{MaxSealedRecords: maxSealed, MaxAuthenticationFailures: 1 << 36}
}

func (s *suite13) Capabilities() cryptosuite.Capabilities {
	return mustAEADCapabilities(
		0,
		tls13AESGCMTagLen,
		tls13SequenceNumberMaskSampleLen,
	)
}

func (s *suite13) NewTrafficProtection(
	trafficSecret cryptosuite.TrafficSecret,
) (cryptosuite.TrafficProtection, error) {
	switch s.algorithm {
	case protection13AESGCM:
		return newAESGCMRecordTrafficProtection13(s.hashFunc, trafficSecret.Bytes(), s.keyLen)
	case protection13ChaCha20Poly1305:
		return newChaCha20Poly1305RecordTrafficProtection13(s.hashFunc, trafficSecret.Bytes())
	default:
		return nil, cryptosuite.ErrInvalidCapabilities
	}
}

//nolint:gochecknoglobals
var builtinCipherSuites = map[cryptosuite.ID]cryptosuite.Suite{
	cryptosuite.TLS_AES_128_GCM_SHA256:       newSuite13(cryptosuite.TLS_AES_128_GCM_SHA256, sha256.New, protection13AESGCM, tls13AES128GCMKeyLen),
	cryptosuite.TLS_AES_256_GCM_SHA384:       newSuite13(cryptosuite.TLS_AES_256_GCM_SHA384, sha512.New384, protection13AESGCM, tls13AES256GCMKeyLen),
	cryptosuite.TLS_CHACHA20_POLY1305_SHA256: newSuite13(cryptosuite.TLS_CHACHA20_POLY1305_SHA256, sha256.New, protection13ChaCha20Poly1305, 0),
}
