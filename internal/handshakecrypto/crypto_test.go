// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package handshakecrypto_test

import (
	"crypto/ecdsa"
	cryptoelliptic "crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"testing"

	"github.com/pion/dtls/v4/internal/crypto/hash"
	"github.com/pion/dtls/v4/internal/crypto/selfsign"
	"github.com/pion/dtls/v4/internal/crypto/signature"
	"github.com/pion/dtls/v4/internal/crypto/signaturehash"
	dtlserrors "github.com/pion/dtls/v4/internal/errors"
	dtlscrypto "github.com/pion/dtls/v4/internal/handshakecrypto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCertificateVerifySchemes(t *testing.T) {
	key, err := ecdsa.GenerateKey(cryptoelliptic.P256(), rand.Reader)
	require.NoError(t, err)
	certificate, err := selfsign.SelfSign(key)
	require.NoError(t, err)
	for _, algorithm := range []hash.Algorithm{hash.SHA256, hash.SHA384, hash.SHA224, hash.SHA1} {
		signed, signErr := dtlscrypto.GenerateCertificateVerify([]byte("transcript"), key, algorithm, signature.ECDSA)
		require.NoError(t, signErr)
		verifyErr := dtlscrypto.VerifyCertificateVerify([]byte("transcript"), algorithm, signature.ECDSA, signed, certificate.Certificate)
		if algorithm != hash.SHA256 {
			assert.ErrorIs(t, verifyErr, dtlserrors.ErrInvalidSignatureAlgorithm)
		} else {
			assert.NoError(t, verifyErr)
		}
	}
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	certificate, err = selfsign.SelfSign(rsaKey)
	require.NoError(t, err)
	signed, err := dtlscrypto.GenerateCertificateVerify([]byte("transcript"), rsaKey, hash.SHA256, signature.RSA)
	require.NoError(t, err)
	assert.ErrorIs(t, dtlscrypto.VerifyCertificateVerify([]byte("transcript"), hash.SHA256, signature.RSA, signed, certificate.Certificate), dtlserrors.ErrInvalidSignatureAlgorithm)
}

// RSA-PSS certificate with id-RSASSA-PSS OID (1.2.840.113549.1.1.10)
// Generated with:
//
//	openssl genpkey -algorithm RSA-PSS -out rsa_pss_key.pem -pkeyopt rsa_keygen_bits:2048
//	openssl req -new -x509 -key rsa_pss_key.pem -out rsa_pss_cert.pem -days 365 -subj "/CN=RSA-PSS-Test"
//
// Note: Go's x509.CreateCertificate does not support creating RSA-PSS certificates,
// and x509.ParsePKCS8PrivateKey cannot parse RSA-PSS private keys (fails with
// "PKCS#8 wrapping contained private key with unknown algorithm: 1.2.840.113549.1.1.10").
// Therefore we use this cert for OID validation testing only.
//
// nolint: gosec
const rsaPSSCertificate = `
-----BEGIN CERTIFICATE-----
MIIDdTCCAimgAwIBAgIUOvVXWgzlj9KVp4TQe+ZATB3PkvswQQYJKoZIhvcNAQEK
MDSgDzANBglghkgBZQMEAgEFAKEcMBoGCSqGSIb3DQEBCDANBglghkgBZQMEAgEF
AKIDAgEgMBcxFTATBgNVBAMMDFJTQS1QU1MtVGVzdDAeFw0yNjAxMjQwNDE1MzFa
Fw0yNzAxMjQwNDE1MzFaMBcxFTATBgNVBAMMDFJTQS1QU1MtVGVzdDCCASAwCwYJ
KoZIhvcNAQEKA4IBDwAwggEKAoIBAQCpwVkHm2eU336pNtW7VYuu7nWUkSZxr9Oz
DAQrZbLsdcSeWj/sSe37/EPmtQrH8f8mK7OR7mY1DrodHyAqyGeeHIwTaAMdrrMX
X0RiPbid7w6MU3QZ1q5Hp8IAf8sLrQofchFRLDw6XkMcI4hbWtVJ9GwZiOO2gpDk
uS7SBLEiEzKHme+UzPMFUa2xCypYd/bpO0F+h9vtPDFTCRfK6EFf7mb/QAl1UwfO
Xq5+hMMiKWyhK2OIKhYc98k7eV7nlC4rz5tMY2v1tUJA6/fAZEmAREVE740hxmkN
qN5Enm5tF/ipROPbmQnyCkwtZxKTLi0tz8RTq7lZXRoQr9fo/6ufAgMBAAGjUzBR
MB0GA1UdDgQWBBRpdc2ssJhWnWTm4DPJLW3aDy71WTAfBgNVHSMEGDAWgBRpdc2s
sJhWnWTm4DPJLW3aDy71WTAPBgNVHRMBAf8EBTADAQH/MEEGCSqGSIb3DQEBCjA0
oA8wDQYJYIZIAWUDBAIBBQChHDAaBgkqhkiG9w0BAQgwDQYJYIZIAWUDBAIBBQCi
AwIBIAOCAQEATkolVgnlASfTEvMElGmrLTRVPBovk7ZCpER+/H316xswuUDWKn9t
BUhSCYinj5yywgwgx4sErnB5YkB+SR2kkE8WMAU0SNTh2kLUr4TrdqM1o0S5hGQT
awGCPIWZjip3V0TeAqC4sWTgdy2EBYPEJ0AZGm50/yJlWiOzsdDbzceKjremCxLF
Qgkrd/H9mRfIsybvQZ0SbhCWTbNiGpv+O3q4rJ8l3FiaNc9xt+9/FbzeRIipmVb3
ACeCkdjZt/3rjb/tZRHcURgXYi2109wQOaIE5tAQYFCvaKp3HNdWGU1K5+AO0SIY
k2mwB2RsEXa29/Xzj1eMyG33CDgo55AtDw==
-----END CERTIFICATE-----
`

// nolint: gosec
const rawPrivateKey = `
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAxIA2BrrnR2sIlATsp7aRBD/3krwZ7vt9dNeoDQAee0s6SuYP
6MBx/HPnAkwNvPS90R05a7pwRkoT6Ur4PfPhCVlUe8lV+0Eto3ZSEeHz3HdsqlM3
bso67L7Dqrc7MdVstlKcgJi8yeAoGOIL9/igOv0XBFCeznm9nznx6mnsR5cugw+1
ypXelaHmBCLV7r5SeVSh57+KhvZGbQ2fFpUaTPegRpJZXBNS8lSeWvtOv9d6N5UB
ROTAJodMZT5AfX0jB0QB9IT/0I96H6BSENH08NXOeXApMuLKvnAf361rS7cRAfRL
rWZqERMP4u6Cnk0Cnckc3WcW27kGGIbtwbqUIQIDAQABAoIBAGF7OVIdZp8Hejn0
N3L8HvT8xtUEe9kS6ioM0lGgvX5s035Uo4/T6LhUx0VcdXRH9eLHnLTUyN4V4cra
ZkxVsE3zAvZl60G6E+oDyLMWZOP6Wu4kWlub9597A5atT7BpMIVCdmFVZFLB4SJ3
AXkC3nplFAYP+Lh1rJxRIrIn2g+pEeBboWbYA++oDNuMQffDZaokTkJ8Bn1JZYh0
xEXKY8Bi2Egd5NMeZa1UFO6y8tUbZfwgVs6Enq5uOgtfayq79vZwyjj1kd29MBUD
8g8byV053ZKxbUOiOuUts97eb+fN3DIDRTcT2c+lXt/4C54M1FclJAbtYRK/qwsl
pYWKQAECgYEA4ZUbqQnTo1ICvj81ifGrz+H4LKQqe92Hbf/W51D/Umk2kP702W22
HP4CvrJRtALThJIG9m2TwUjl/WAuZIBrhSAbIvc3Fcoa2HjdRp+sO5U1ueDq7d/S
Z+PxRI8cbLbRpEdIaoR46qr/2uWZ943PHMv9h4VHPYn1w8b94hwD6vkCgYEA3v87
mFLzyM9ercnEv9zHMRlMZFQhlcUGQZvfb8BuJYl/WogyT6vRrUuM0QXULNEPlrin
mBQTqc1nCYbgkFFsD2VVt1qIyiAJsB9MD1LNV6YuvE7T2KOSadmsA4fa9PUqbr71
hf3lTTq+LeR09LebO7WgSGYY+5YKVOEGpYMR1GkCgYEAxPVQmk3HKHEhjgRYdaG5
lp9A9ZE8uruYVJWtiHgzBTxx9TV2iST+fd/We7PsHFTfY3+wbpcMDBXfIVRKDVwH
BMwchXH9+Ztlxx34bYJaegd0SmA0Hw9ugWEHNgoSEmWpM1s9wir5/ELjc7dGsFtz
uzvsl9fpdLSxDYgAAdzeGtkCgYBAzKIgrVox7DBzB8KojhtD5ToRnXD0+H/M6OKQ
srZPKhlb0V/tTtxrIx0UUEFLlKSXA6mPw6XDHfDnD86JoV9pSeUSlrhRI+Ysy6tq
eIE7CwthpPZiaYXORHZ7wCqcK/HcpJjsCs9rFbrV0yE5S3FMdIbTAvgXg44VBB7O
UbwIoQKBgDuY8gSrA5/A747wjjmsdRWK4DMTMEV4eCW1BEP7Tg7Cxd5n3xPJiYhr
nhLGN+mMnVIcv2zEMS0/eNZr1j/0BtEdx+3IC6Eq+ONY0anZ4Irt57/5QeKgKn/L
JPhfPySIPG4UmwE4gW8t79vfOKxnUu2fDD1ZXUYopan6EckACNH/
-----END RSA PRIVATE KEY-----
`

func TestRSAPSSSignatureGeneration(t *testing.T) {
	expectedMsg := []byte("CertificateVerify input")

	// Parse the private key
	block, _ := pem.Decode([]byte(rawPrivateKey))
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	assert.NoError(t, err)

	// Generate PSS signature
	sig, err := dtlscrypto.GenerateCertificateVerify(expectedMsg, key, hash.SHA256, signature.RSA_PSS_RSAE_SHA256)
	assert.NoError(t, err)
	assert.NotNil(t, sig)

	// Verify that PSS signature is different from PKCS#1 v1.5 (PSS is randomized)
	sig2, err := dtlscrypto.GenerateCertificateVerify(expectedMsg, key, hash.SHA256, signature.RSA_PSS_RSAE_SHA256)
	assert.NoError(t, err)
	// PSS signatures should be different each time due to random salt
	assert.NotEqual(t, sig, sig2)
}

func TestRSAPSSSignatureVerification(t *testing.T) {
	expectedMsg := []byte("CertificateVerify input")

	// Parse the private key
	block, _ := pem.Decode([]byte(rawPrivateKey))
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	assert.NoError(t, err)

	// Generate certificate with the public key
	cert := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		PublicKey:    &key.PublicKey,
	}
	rawCert, err := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	assert.NoError(t, err)

	// Generate PSS signature
	sig, err := dtlscrypto.GenerateCertificateVerify(expectedMsg, key, hash.SHA256, signature.RSA_PSS_RSAE_SHA256)
	assert.NoError(t, err)

	// Verify PSS signature
	err = dtlscrypto.VerifyCertificateVerify(expectedMsg, hash.SHA256, signature.RSA_PSS_RSAE_SHA256, sig, [][]byte{rawCert})
	assert.NoError(t, err)

	// Verify that PKCS#1 v1.5 verification fails for PSS signature
	err = dtlscrypto.VerifyCertificateVerify(expectedMsg, hash.SHA256, signature.RSA, sig, [][]byte{rawCert})
	assert.Error(t, err)
}

func TestRSAPSSVsPKCS1v15(t *testing.T) {
	expectedMsg := []byte("CertificateVerify input")

	// Parse the private key
	block, _ := pem.Decode([]byte(rawPrivateKey))
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	assert.NoError(t, err)

	// Generate certificate
	cert := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		PublicKey:    &key.PublicKey,
	}
	rawCert, err := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	assert.NoError(t, err)

	// DTLS 1.3 does not allow PKCS#1 v1.5 in CertificateVerify.
	pkcs1Sig, err := dtlscrypto.GenerateCertificateVerify(expectedMsg, key, hash.SHA256, signature.RSA)
	assert.NoError(t, err)
	err = dtlscrypto.VerifyCertificateVerify(expectedMsg, hash.SHA256, signature.RSA, pkcs1Sig, [][]byte{rawCert})
	assert.ErrorIs(t, err, dtlserrors.ErrInvalidSignatureAlgorithm)

	// Generate and verify PSS signature
	pssSig, err := dtlscrypto.GenerateCertificateVerify(expectedMsg, key, hash.SHA256, signature.RSA_PSS_RSAE_SHA256)
	assert.NoError(t, err)
	err = dtlscrypto.VerifyCertificateVerify(expectedMsg, hash.SHA256, signature.RSA_PSS_RSAE_SHA256, pssSig, [][]byte{rawCert})
	assert.NoError(t, err)

	// Verify cross-verification fails
	err = dtlscrypto.VerifyCertificateVerify(expectedMsg, hash.SHA256, signature.RSA_PSS_RSAE_SHA256, pkcs1Sig, [][]byte{rawCert})
	assert.Error(t, err, "PKCS#1 v1.5 signature should not verify as PSS")

	err = dtlscrypto.VerifyCertificateVerify(expectedMsg, hash.SHA256, signature.RSA, pssSig, [][]byte{rawCert})
	assert.Error(t, err, "PSS signature should not verify as PKCS#1 v1.5")
}

func TestRSAPSSRSAEVariants(t *testing.T) {
	expectedMsg := []byte("CertificateVerify input")

	// Parse the private key
	block, _ := pem.Decode([]byte(rawPrivateKey))
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	assert.NoError(t, err)

	// Generate certificate with rsaEncryption OID (standard RSA cert)
	cert := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		PublicKey:    &key.PublicKey,
	}
	rawCert, err := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	assert.NoError(t, err)

	// Test RSA-PSS RSAE variants (work with standard RSA certs)
	// Note: We don't test RSA_PSS_PSS variants here because they require id-RSASSA-PSS OID certs,
	// which Go's x509.CreateCertificate doesn't support creating (and can't parse properly either).
	// OID validation is tested separately in TestCertificateOIDValidation.
	testCases := []struct {
		name     string
		hashAlgo hash.Algorithm
		sigAlgo  signature.Algorithm
	}{
		{"RSA_PSS_RSAE_SHA256", hash.SHA256, signature.RSA_PSS_RSAE_SHA256},
		{"RSA_PSS_RSAE_SHA384", hash.SHA384, signature.RSA_PSS_RSAE_SHA384},
		{"RSA_PSS_RSAE_SHA512", hash.SHA512, signature.RSA_PSS_RSAE_SHA512},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Generate signature
			sig, err := dtlscrypto.GenerateCertificateVerify(expectedMsg, key, tc.hashAlgo, tc.sigAlgo)
			assert.NoError(t, err)
			assert.NotNil(t, sig)
			assert.True(t, len(sig) > 0, "Signature should not be empty")

			// Verify signature
			err = dtlscrypto.VerifyCertificateVerify(expectedMsg, tc.hashAlgo, tc.sigAlgo, sig, [][]byte{rawCert})
			assert.NoError(t, err, "Signature verification should succeed")

			// Verify IsPSS() returns true
			assert.True(t, tc.sigAlgo.IsPSS(), "Should be identified as PSS algorithm")

			// Verify GetPSSHash() returns correct hash
			assert.Equal(t, tc.hashAlgo, tc.sigAlgo.GetPSSHash(), "Hash extraction should match")
		})
	}
}

func TestCertificateOIDValidation(t *testing.T) {
	expectedMsg := []byte("CertificateVerify input")

	// Load standard RSA key and cert (has rsaEncryption OID)
	block, _ := pem.Decode([]byte(rawPrivateKey))
	rsaKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	assert.NoError(t, err)

	rsaEncryptionCert := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		PublicKey:    &rsaKey.PublicKey,
	}
	rsaEncryptionCertBytes, err := x509.CreateCertificate(rand.Reader, rsaEncryptionCert, rsaEncryptionCert, &rsaKey.PublicKey, rsaKey)
	assert.NoError(t, err)

	// Load RSA-PSS cert (has id-RSASSA-PSS OID)
	// We use a locally generated RSA-PSS cert since Go's x509.CreateCertificate doesn't support creating them.
	// We use the regular RSA key for signing because Go can't parse RSA-PSS private keys either.
	// For OID validation testing, only the cert's OID matters, not which key was used to sign.
	pssCertBlock, _ := pem.Decode([]byte(rsaPSSCertificate))
	pssCertBytes := pssCertBlock.Bytes

	t.Run("RSAE_with_rsaEncryption_OID_succeeds", func(t *testing.T) {
		// Generate signature with RSAE algorithm using rsaEncryption cert
		sig, err := dtlscrypto.GenerateCertificateVerify(expectedMsg, rsaKey, hash.SHA256, signature.RSA_PSS_RSAE_SHA256)
		assert.NoError(t, err)

		// Should succeed: RSAE + rsaEncryption OID is valid per RFC 8446
		err = dtlscrypto.VerifyCertificateVerify(expectedMsg, hash.SHA256, signature.RSA_PSS_RSAE_SHA256, sig, [][]byte{rsaEncryptionCertBytes})
		assert.NoError(t, err)
	})

	t.Run("PSS_with_idRSASSAPSS_OID_succeeds", func(t *testing.T) {
		t.Skip("Go's x509 library cannot extract public key from RSA-PSS certificates (OID 1.2.840.113549.1.1.10)")
		// This test would verify that PSS + id-RSASSA-PSS OID is valid per RFC 8446,
		// but Go's crypto/x509 doesn't fully support parsing RSA-PSS certs.
		// The important validation (that mismatches are rejected) is tested in other cases.
	})

	t.Run("PSS_with_rsaEncryption_OID_fails", func(t *testing.T) {
		// Generate signature with PSS algorithm
		sig, err := dtlscrypto.GenerateCertificateVerify(expectedMsg, rsaKey, hash.SHA256, signature.RSA_PSS_PSS_SHA256)
		assert.NoError(t, err)

		// Should fail: PSS algorithm requires id-RSASSA-PSS OID, not rsaEncryption
		err = dtlscrypto.VerifyCertificateVerify(expectedMsg, hash.SHA256, signature.RSA_PSS_PSS_SHA256, sig, [][]byte{rsaEncryptionCertBytes})
		assert.Error(t, err)
		assert.ErrorIs(t, err, dtlserrors.ErrInvalidCertificateOID)
	})

	t.Run("RSAE_with_idRSASSAPSS_OID_fails", func(t *testing.T) {
		// Generate signature with RSAE algorithm
		sig, err := dtlscrypto.GenerateCertificateVerify(expectedMsg, rsaKey, hash.SHA256, signature.RSA_PSS_RSAE_SHA256)
		assert.NoError(t, err)

		// Should fail: RSAE algorithm requires rsaEncryption OID, not id-RSASSA-PSS
		err = dtlscrypto.VerifyCertificateVerify(expectedMsg, hash.SHA256, signature.RSA_PSS_RSAE_SHA256, sig, [][]byte{pssCertBytes})
		assert.Error(t, err)
		assert.ErrorIs(t, err, dtlserrors.ErrInvalidCertificateOID)
	})
}

func TestValidateCertificateSignatureAlgorithms(t *testing.T) {
	type certSpec struct {
		algorithm x509.SignatureAlgorithm
		isCA      bool
	}
	rsa256 := signaturehash.Algorithm{Hash: hash.SHA256, Signature: signature.RSA}
	ecdsa384 := signaturehash.Algorithm{Hash: hash.SHA384, Signature: signature.ECDSA}
	tests := map[string]struct {
		certs    []certSpec
		allowed  []signaturehash.Algorithm
		wantErr  error
		anyError bool
	}{
		"Empty allowed list passes": {
			certs: []certSpec{{x509.SHA256WithRSA, false}},
		},
		"Single cert with allowed algorithm passes": {
			certs: []certSpec{{x509.SHA256WithRSA, false}, {x509.SHA256WithRSA, true}}, allowed: []signaturehash.Algorithm{rsa256},
		},
		"Single cert with disallowed algorithm fails": {
			certs: []certSpec{{x509.SHA256WithRSA, false}, {x509.SHA256WithRSA, true}}, allowed: []signaturehash.Algorithm{ecdsa384},
			wantErr: dtlserrors.ErrInvalidCertificateSignatureAlgorithm,
		},
		"Root certificate is not validated": {
			certs: []certSpec{{x509.SHA256WithRSA, false}, {x509.SHA384WithRSA, true}}, allowed: []signaturehash.Algorithm{rsa256},
		},
		"Multi-cert chain with all allowed algorithms passes":     {certs: []certSpec{{x509.SHA256WithRSA, false}, {x509.SHA384WithRSA, false}, {x509.SHA512WithRSA, true}}, allowed: []signaturehash.Algorithm{rsa256, {Hash: hash.SHA384, Signature: signature.RSA}}},
		"Multi-cert chain with one disallowed intermediate fails": {certs: []certSpec{{x509.SHA256WithRSA, false}, {x509.SHA384WithRSA, false}, {x509.SHA512WithRSA, true}}, allowed: []signaturehash.Algorithm{rsa256}, wantErr: dtlserrors.ErrInvalidCertificateSignatureAlgorithm},
		"ECDSA certificates": {certs: []certSpec{{x509.ECDSAWithSHA256, false}, {x509.ECDSAWithSHA384, false}, {x509.ECDSAWithSHA512, true}}, allowed: []signaturehash.Algorithm{{Hash: hash.SHA256, Signature: signature.ECDSA}, ecdsa384}},
		"RSA-PSS certificates": {
			certs: []certSpec{{x509.SHA256WithRSAPSS, false}, {x509.SHA384WithRSAPSS, true}}, allowed: []signaturehash.Algorithm{{Hash: hash.SHA256, Signature: signature.RSA_PSS_RSAE_SHA256}},
		},
		"Ed25519 certificates": {certs: []certSpec{{x509.PureEd25519, false}, {x509.PureEd25519, true}}, allowed: []signaturehash.Algorithm{{Hash: hash.None, Signature: signature.Ed25519}}},
		"Unsupported certificate algorithm": {
			certs: []certSpec{{x509.MD5WithRSA, false}, {x509.SHA256WithRSA, true}}, allowed: []signaturehash.Algorithm{rsa256}, anyError: true,
		},
		"Single cert chain does not validate": {certs: []certSpec{{x509.SHA256WithRSA, true}}, allowed: []signaturehash.Algorithm{ecdsa384}},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			certs := make([]*x509.Certificate, len(test.certs))
			for i, cert := range test.certs {
				certs[i] = &x509.Certificate{SerialNumber: big.NewInt(1), SignatureAlgorithm: cert.algorithm, IsCA: cert.isCA}
			}
			err := dtlscrypto.ValidateCertificateSignatureAlgorithms(certs, test.allowed)
			if test.anyError {
				assert.Error(t, err)
			} else {
				assert.ErrorIs(t, err, test.wantErr)
			}
		})
	}
}
