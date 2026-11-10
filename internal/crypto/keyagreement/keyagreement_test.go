// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package keyagreement

import (
	"crypto/ecdh"
	"crypto/rand"
	"testing"

	"github.com/pion/dtls/v4/internal/crypto/elliptic"
	dtlserrors "github.com/pion/dtls/v4/internal/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSharedSecret(t *testing.T) {
	privateKey := []byte{0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f}
	publicKey := []byte{0x9f, 0xd7, 0xad, 0x6d, 0xcf, 0xf4, 0x29, 0x8d, 0xd3, 0xf9, 0x6d, 0x5b, 0x1b, 0x2a, 0xf9, 0x10, 0xa0, 0x53, 0x5b, 0x14, 0x88, 0xd7, 0xf8, 0xfa, 0xbb, 0x34, 0x9a, 0x98, 0x28, 0x80, 0xb6, 0x15}
	expectedSharedSecret := []byte{0xdf, 0x4a, 0x29, 0x1b, 0xaa, 0x1e, 0xb7, 0xcf, 0xa6, 0x93, 0x4b, 0x29, 0xb4, 0x74, 0xba, 0xad, 0x26, 0x97, 0xe2, 0x9f, 0x1f, 0x92, 0x0d, 0xcc, 0x77, 0xc8, 0xa0, 0xa0, 0x88, 0x44, 0x76, 0x24}

	sharedSecret, err := SharedSecret(publicKey, privateKey, elliptic.X25519)
	assert.NoError(t, err)
	assert.Equal(t, expectedSharedSecret, sharedSecret)
}

func TestSharedSecret_X25519MLKEM768(t *testing.T) {
	clientKeypair, err := elliptic.GenerateKeypair(elliptic.X25519MLKEM768)
	require.NoError(t, err)
	serverKeypair, err := elliptic.GenerateKeypairForPeer(elliptic.X25519MLKEM768, clientKeypair.PublicKey)
	require.NoError(t, err)

	clientSecret, err := SharedSecret(
		serverKeypair.PublicKey,
		clientKeypair.PrivateKey,
		elliptic.X25519MLKEM768,
	)
	require.NoError(t, err)
	serverSecret, err := SharedSecret(
		clientKeypair.PublicKey,
		serverKeypair.PrivateKey,
		elliptic.X25519MLKEM768,
	)
	require.NoError(t, err)

	assert.Equal(t, serverSecret, clientSecret)
	assert.Len(t, clientSecret, elliptic.X25519MLKEM768SharedSecretSize)
}

func TestSharedSecret_InvalidCurve(t *testing.T) {
	invalid := elliptic.Curve(0) // not supported
	_, err := SharedSecret(nil, nil, invalid)
	assert.ErrorIs(t, err, dtlserrors.ErrInvalidNamedCurve)
}

func TestSharedSecret_X25519MLKEM768RejectsBadShareLengths(t *testing.T) {
	clientKeypair, err := elliptic.GenerateKeypair(elliptic.X25519MLKEM768)
	require.NoError(t, err)

	_, err = SharedSecret([]byte{0x01}, clientKeypair.PrivateKey, elliptic.X25519MLKEM768)
	assert.ErrorIs(t, err, dtlserrors.ErrLengthMismatch)

	_, err = SharedSecret(clientKeypair.PublicKey, []byte{0x01}, elliptic.X25519MLKEM768)
	assert.ErrorIs(t, err, dtlserrors.ErrLengthMismatch)
}

func TestSharedSecret_NewPrivateKeyError(t *testing.T) {
	// P-256 with invalid private key length -> ec.NewPrivateKey error.
	curve := elliptic.P256
	priv := []byte{}    // invalid size for P-256 (needs 32 bytes)
	pub := []byte{0x04} // won't be reached, set something anyways

	_, err := SharedSecret(pub, priv, curve)
	assert.Error(t, err) // error from ec.NewPrivateKey
}

func TestSharedSecret_NewPublicKeyError(t *testing.T) {
	// valid P-256 private key with invalid public key encoding -> ec.NewPublicKey error.
	ec := ecdh.P256()
	sk, err := ec.GenerateKey(rand.Reader)
	assert.NoError(t, err)

	priv := sk.Bytes()
	invalidPub := []byte{0x04, 0x01, 0x02} // invalid but wrong length

	_, err = SharedSecret(invalidPub, priv, elliptic.P256)
	assert.Error(t, err) // error from ec.NewPublicKey
}

func TestSharedSecret_P256_Success_CaseHit(t *testing.T) {
	// P-256 case branch and confirm success (non-empty shared secret).
	ec := ecdh.P256()
	aliceSK, err := ec.GenerateKey(rand.Reader)
	assert.NoError(t, err)

	bobSK, err := ec.GenerateKey(rand.Reader)
	assert.NoError(t, err)

	// Expected shared secret using ecdh directly.
	exp, err := aliceSK.ECDH(bobSK.PublicKey())
	assert.NoError(t, err)
	assert.NotEmpty(t, exp)

	secret, err := SharedSecret(bobSK.PublicKey().Bytes(), aliceSK.Bytes(), elliptic.P256)
	assert.NoError(t, err)
	assert.NotEmpty(t, secret)
	assert.Equal(t, exp, secret) // exact match
}
