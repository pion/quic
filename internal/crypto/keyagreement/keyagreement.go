// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

// Package keyagreement computes the (EC)DHE shared secret for a negotiated
// group. The result is the input to the DTLS 1.3 key schedule.
// https://www.rfc-editor.org/rfc/rfc8446#section-7.4
package keyagreement

import (
	"crypto/ecdh"
	"crypto/mlkem"

	"github.com/pion/dtls/v4/internal/crypto/elliptic"
	dtlserrors "github.com/pion/dtls/v4/internal/errors"
)

// SharedSecret implements ECDHE and hybrid key agreement for a peer public
// key, local private key, and negotiated group.
func SharedSecret(publicKey, privateKey []byte, curve elliptic.Curve) ([]byte, error) {
	if curve == elliptic.X25519MLKEM768 {
		return x25519MLKEM768SharedSecret(publicKey, privateKey)
	}

	return ecdhSharedSecret(publicKey, privateKey, curve)
}

func ecdhSharedSecret(publicKey, privateKey []byte, curve elliptic.Curve) ([]byte, error) {
	var ec ecdh.Curve

	switch curve {
	case elliptic.X25519:
		ec = ecdh.X25519()
	case elliptic.P256:
		ec = ecdh.P256()
	case elliptic.P384:
		ec = ecdh.P384()
	default:
		return nil, dtlserrors.ErrInvalidNamedCurve
	}

	sk, err := ec.NewPrivateKey(privateKey)
	if err != nil {
		return nil, err
	}

	pk, err := ec.NewPublicKey(publicKey) // NIST: SEC1 uncompressed; X25519: 32-byte u
	if err != nil {
		return nil, err
	}

	return sk.ECDH(pk)
}

func x25519MLKEM768SharedSecret(publicKey, privateKey []byte) ([]byte, error) {
	switch len(privateKey) {
	case elliptic.X25519MLKEM768ClientPrivateKeySize:
		return x25519MLKEM768ClientSharedSecret(publicKey, privateKey)
	case elliptic.X25519MLKEM768ServerPrivateKeySize:
		return x25519MLKEM768ServerSharedSecret(publicKey, privateKey)
	default:
		return nil, dtlserrors.ErrLengthMismatch
	}
}

func x25519MLKEM768ClientSharedSecret(serverPublicKey, clientPrivateKey []byte) ([]byte, error) {
	if len(serverPublicKey) != elliptic.X25519MLKEM768ServerPublicKeySize {
		return nil, dtlserrors.ErrLengthMismatch
	}

	mlkemSecretKey, err := mlkem.NewDecapsulationKey768(clientPrivateKey[:mlkem.SeedSize])
	if err != nil {
		return nil, err
	}

	mlkemSharedKey, err := mlkemSecretKey.Decapsulate(serverPublicKey[:mlkem.CiphertextSize768])
	if err != nil {
		return nil, err
	}

	x25519SharedKey, err := ecdhSharedSecret(serverPublicKey[mlkem.CiphertextSize768:], clientPrivateKey[mlkem.SeedSize:], elliptic.X25519)
	if err != nil {
		return nil, err
	}

	secret := make([]byte, 0, elliptic.X25519MLKEM768SharedSecretSize)
	secret = append(secret, mlkemSharedKey...)
	secret = append(secret, x25519SharedKey...)

	return secret, nil
}

func x25519MLKEM768ServerSharedSecret(clientPublicKey, serverPrivateKey []byte) ([]byte, error) {
	if len(clientPublicKey) != elliptic.X25519MLKEM768ClientPublicKeySize {
		return nil, dtlserrors.ErrLengthMismatch
	}

	x25519SharedKey, err := ecdhSharedSecret(clientPublicKey[mlkem.EncapsulationKeySize768:], serverPrivateKey[mlkem.SharedKeySize:], elliptic.X25519)
	if err != nil {
		return nil, err
	}

	secret := make([]byte, 0, elliptic.X25519MLKEM768SharedSecretSize)
	secret = append(secret, serverPrivateKey[:mlkem.SharedKeySize]...)
	secret = append(secret, x25519SharedKey...)

	return secret, nil
}
