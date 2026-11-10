// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

// Package handshakecrypto contains internal handshake cryptography helpers.
package handshakecrypto

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	cryptoelliptic "crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"time"

	"github.com/pion/dtls/v4/internal/crypto/hash"
	"github.com/pion/dtls/v4/internal/crypto/signature"
	"github.com/pion/dtls/v4/internal/crypto/signaturehash"
	dtlserrors "github.com/pion/dtls/v4/internal/errors"
)

type ecdsaSignature struct {
	R, S *big.Int
}

// Match crypto/tls's default limit on peer RSA keys.
const maxPeerRSAKeyBits = 8192

func parsePeerCertificate(raw []byte) (*x509.Certificate, error) {
	cert, err := x509.ParseCertificate(raw)
	if err != nil {
		return nil, err
	}
	if key, ok := cert.PublicKey.(*rsa.PublicKey); ok && key.N.BitLen() > maxPeerRSAKeyBits {
		return nil, dtlserrors.ErrPeerRSAKeyTooLarge
	}

	return cert, nil
}

// validateSignatureAlgOID validates that the signature scheme matches the
// certificate's public key algorithm OID. This is required by RFC 8446 Section 4.2.3:
// - RSA_PSS_RSAE requires rsaEncryption OID
// - RSA_PSS_PSS requires id-RSASSA-PSS OID
//
// Note: returns nil if the given signature.Algorithm is not PSS based.
//
// https://www.rfc-editor.org/rfc/rfc8446#section-4.2.3
func validateSignatureAlgOID(cert *x509.Certificate, sigAlg signature.Algorithm) error {
	if !sigAlg.IsPSS() {
		return nil
	}

	// Get the certificate's public key algorithm OID from the raw certificate
	// We need to parse the SubjectPublicKeyInfo to get the algorithm OID
	var spki struct {
		Algorithm pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	}
	if _, err := asn1.Unmarshal(cert.RawSubjectPublicKeyInfo, &spki); err != nil {
		return err
	}

	certOID := spki.Algorithm.Algorithm

	switch sigAlg {
	// Check RSAE variants (0x0804-0x0806) require rsaEncryption OID
	case signature.RSA_PSS_RSAE_SHA256, signature.RSA_PSS_RSAE_SHA384, signature.RSA_PSS_RSAE_SHA512:
		oidPublicKeyRSA := asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1} // OID: rsaEncryption
		if !certOID.Equal(oidPublicKeyRSA) {
			return dtlserrors.ErrInvalidCertificateOID
		}

		return nil

	// Check PSS variants (0x0809-0x080b) require id-RSASSA-PSS OID
	case signature.RSA_PSS_PSS_SHA256, signature.RSA_PSS_PSS_SHA384, signature.RSA_PSS_PSS_SHA512:
		oidPublicKeyRSAPSS := asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 10} // OID: id-RSASSA-PSS
		if !certOID.Equal(oidPublicKeyRSAPSS) {
			return dtlserrors.ErrInvalidCertificateOID
		}

		return nil

	default:
		return nil
	}
}

func validateHandshakeSignatureScheme(
	publicKey crypto.PublicKey,
	hashAlgorithm hash.Algorithm,
	signatureAlgorithm signature.Algorithm,
) error {
	if _, ok := publicKey.(ed25519.PublicKey); ok {
		if signatureAlgorithm == signature.Ed25519 && hashAlgorithm == hash.Ed25519 {
			return nil
		}

		return dtlserrors.ErrInvalidSignatureAlgorithm
	}
	if hashAlgorithm.CryptoHash() == 0 {
		return dtlserrors.ErrInvalidSignatureAlgorithm
	}
	switch publicKey.(type) {
	case *ecdsa.PublicKey:
		if signatureAlgorithm == signature.ECDSA {
			return nil
		}
	case *rsa.PublicKey:
		// GetPSSHash returns hash.None for non-PSS schemes, which the
		// nonzero hash check above already excludes.
		if signatureAlgorithm == signature.RSA ||
			signatureAlgorithm.GetPSSHash() == hashAlgorithm {
			return nil
		}
	}

	return dtlserrors.ErrInvalidSignatureAlgorithm
}

// GenerateCertificateVerify signs the DTLS 1.3 CertificateVerify input.
// https://www.rfc-editor.org/rfc/rfc8446#section-4.4.3
func GenerateCertificateVerify(handshakeBodies []byte, signer crypto.Signer, hashAlgorithm hash.Algorithm, signatureAlgorithm signature.Algorithm) ([]byte, error) {
	if err := validateHandshakeSignatureScheme(signer.Public(), hashAlgorithm, signatureAlgorithm); err != nil {
		return nil, err
	}
	if _, ok := signer.Public().(ed25519.PublicKey); ok {
		// https://pkg.go.dev/crypto/ed25519#PrivateKey.Sign
		// Sign signs the given message with priv. Ed25519 performs two passes over
		// messages to be signed and therefore cannot handle pre-hashed messages.
		return signer.Sign(rand.Reader, handshakeBodies, crypto.Hash(0))
	}

	hashed := hashAlgorithm.Digest(handshakeBodies)

	switch signer.Public().(type) {
	case *ecdsa.PublicKey:
		return signer.Sign(rand.Reader, hashed, hashAlgorithm.CryptoHash())
	case *rsa.PublicKey:
		// Use RSA-PSS if the signature algorithm is PSS
		if signatureAlgorithm.IsPSS() {
			pssOpts := &rsa.PSSOptions{
				SaltLength: rsa.PSSSaltLengthEqualsHash,
				Hash:       hashAlgorithm.CryptoHash(),
			}

			return signer.Sign(rand.Reader, hashed, pssOpts)
		}

		// Otherwise use PKCS#1 v1.5
		return signer.Sign(rand.Reader, hashed, hashAlgorithm.CryptoHash())
	}

	return nil, dtlserrors.ErrInvalidSignatureAlgorithm
}

// VerifyCertificateVerify verifies a DTLS 1.3 CertificateVerify signature.
func VerifyCertificateVerify(message []byte, hashAlgorithm hash.Algorithm, signatureAlgorithm signature.Algorithm, remoteKeySignature []byte, rawCertificates [][]byte) error {
	if len(rawCertificates) == 0 {
		return dtlserrors.ErrLengthMismatch
	}
	certificate, err := parsePeerCertificate(rawCertificates[0])
	if err != nil {
		return err
	}

	// Validate that the signature algorithm matches the certificate's OID
	if err := validateSignatureAlgOID(certificate, signatureAlgorithm); err != nil {
		return err
	}

	if err := validateSignatureScheme13(certificate.PublicKey, hashAlgorithm, signatureAlgorithm); err != nil {
		return err
	}

	switch pubKey := certificate.PublicKey.(type) {
	case ed25519.PublicKey:
		if ok := ed25519.Verify(pubKey, message, remoteKeySignature); !ok {
			return dtlserrors.ErrKeySignatureMismatch
		}

		return nil
	case *ecdsa.PublicKey:
		return verifyECDSACertificateSignature(pubKey, message, remoteKeySignature, hashAlgorithm)
	case *rsa.PublicKey:
		return verifyRSACertificateSignature(pubKey, message, remoteKeySignature, hashAlgorithm, signatureAlgorithm)
	}

	return dtlserrors.ErrInvalidSignatureAlgorithm
}

// DTLS 1.3 forbids PKCS#1 v1.5, SHA-1, and SHA-224 in CertificateVerify, and
// binds each ECDSA scheme to one curve.
// https://www.rfc-editor.org/rfc/rfc8446#section-4.2.3
func validateSignatureScheme13(key crypto.PublicKey, hashAlgorithm hash.Algorithm, signatureAlgorithm signature.Algorithm) error {
	if signatureAlgorithm == signature.RSA || hashAlgorithm.Insecure() || hashAlgorithm == hash.SHA224 {
		return dtlserrors.ErrInvalidSignatureAlgorithm
	}
	if publicKey, ok := key.(*ecdsa.PublicKey); ok && !matchesECDSACurve13(publicKey, hashAlgorithm) {
		return dtlserrors.ErrInvalidSignatureAlgorithm
	}

	return validateHandshakeSignatureScheme(key, hashAlgorithm, signatureAlgorithm)
}

func matchesECDSACurve13(key *ecdsa.PublicKey, hashAlgorithm hash.Algorithm) bool {
	return (key.Curve == cryptoelliptic.P256() && hashAlgorithm == hash.SHA256) ||
		(key.Curve == cryptoelliptic.P384() && hashAlgorithm == hash.SHA384) ||
		(key.Curve == cryptoelliptic.P521() && hashAlgorithm == hash.SHA512)
}

func verifyRSACertificateSignature(pubKey *rsa.PublicKey, message, remoteKeySignature []byte, hashAlgorithm hash.Algorithm, signatureAlgorithm signature.Algorithm) error {
	hashed := hashAlgorithm.Digest(message)

	// Use RSA-PSS verification if the signature algorithm is PSS
	if signatureAlgorithm.IsPSS() {
		pssOpts := &rsa.PSSOptions{
			SaltLength: rsa.PSSSaltLengthEqualsHash,
			Hash:       hashAlgorithm.CryptoHash(),
		}
		if err := rsa.VerifyPSS(pubKey, hashAlgorithm.CryptoHash(), hashed, remoteKeySignature, pssOpts); err != nil {
			return dtlserrors.ErrKeySignatureMismatch
		}

		return nil
	}

	// Otherwise use PKCS#1 v1.5
	if rsa.VerifyPKCS1v15(pubKey, hashAlgorithm.CryptoHash(), hashed, remoteKeySignature) != nil {
		return dtlserrors.ErrKeySignatureMismatch
	}

	return nil
}

func verifyECDSACertificateSignature(pubKey *ecdsa.PublicKey, message, remoteKeySignature []byte, hashAlgorithm hash.Algorithm) error {
	ecdsaSig := &ecdsaSignature{}
	if _, err := asn1.Unmarshal(remoteKeySignature, ecdsaSig); err != nil {
		return err
	}
	if ecdsaSig.R.Sign() <= 0 || ecdsaSig.S.Sign() <= 0 {
		return dtlserrors.ErrInvalidECDSASignature
	}
	hashed := hashAlgorithm.Digest(message)
	if !ecdsa.Verify(pubKey, hashed, ecdsaSig.R, ecdsaSig.S) {
		return dtlserrors.ErrKeySignatureMismatch
	}

	return nil
}

func loadCerts(rawCertificates [][]byte) ([]*x509.Certificate, error) {
	if len(rawCertificates) == 0 {
		return nil, dtlserrors.ErrLengthMismatch
	}

	certs := make([]*x509.Certificate, 0, len(rawCertificates))
	for _, rawCert := range rawCertificates {
		cert, err := parsePeerCertificate(rawCert)
		if err != nil {
			return nil, err
		}
		certs = append(certs, cert)
	}

	return certs, nil
}

func VerifyClientCert(rawCertificates [][]byte, roots *x509.CertPool, certSignatureSchemes []signaturehash.Algorithm) (chains [][]*x509.Certificate, err error) {
	certificate, err := loadCerts(rawCertificates)
	if err != nil {
		return nil, err
	}
	intermediateCAPool := x509.NewCertPool()
	for _, cert := range certificate[1:] {
		intermediateCAPool.AddCert(cert)
	}
	opts := x509.VerifyOptions{Roots: roots, CurrentTime: time.Now(), Intermediates: intermediateCAPool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}

	chains, err = certificate[0].Verify(opts)
	if err != nil {
		return nil, err
	}

	// Validate certificate signature algorithms if specified.
	// At least one chain must use only allowed signature algorithms.
	if len(certSignatureSchemes) > 0 && len(chains) > 0 {
		var validChainFound bool
		for _, chain := range chains {
			if err := ValidateCertificateSignatureAlgorithms(chain, certSignatureSchemes); err == nil {
				validChainFound = true

				break
			}
		}
		if !validChainFound {
			return nil, dtlserrors.ErrInvalidCertificateSignatureAlgorithm
		}
	}

	return chains, nil
}

func VerifyServerCert(rawCertificates [][]byte, roots *x509.CertPool, serverName string, certSignatureSchemes []signaturehash.Algorithm) (chains [][]*x509.Certificate, err error) {
	certificate, err := loadCerts(rawCertificates)
	if err != nil {
		return nil, err
	}
	intermediateCAPool := x509.NewCertPool()
	for _, cert := range certificate[1:] {
		intermediateCAPool.AddCert(cert)
	}
	opts := x509.VerifyOptions{Roots: roots, CurrentTime: time.Now(), DNSName: serverName, Intermediates: intermediateCAPool}

	chains, err = certificate[0].Verify(opts)
	if err != nil {
		return nil, err
	}

	// Validate certificate signature algorithms if specified.
	// At least one chain must use only allowed signature algorithms.
	if len(certSignatureSchemes) > 0 && len(chains) > 0 {
		var validChainFound bool
		for _, chain := range chains {
			if err := ValidateCertificateSignatureAlgorithms(chain, certSignatureSchemes); err == nil {
				validChainFound = true

				break
			}
		}
		if !validChainFound {
			return nil, dtlserrors.ErrInvalidCertificateSignatureAlgorithm
		}
	}

	return chains, nil
}

// ValidateCertificateSignatureAlgorithms validates that all certificates in the chain
// use signature algorithms that are in the allowed list. This implements the
// signature_algorithms_cert extension validation per RFC 8446 Section 4.2.3.
func ValidateCertificateSignatureAlgorithms(certs []*x509.Certificate, allowedAlgorithms []signaturehash.Algorithm) error {
	if len(allowedAlgorithms) == 0 {
		// No restrictions specified
		return nil
	}

	// Validate each certificate's signature algorithm (except the root, which we trust)
	for i := 0; i < len(certs)-1; i++ {
		cert := certs[i]
		certAlg, err := signaturehash.FromCertificate(cert)
		if err != nil {
			return err
		}

		// Check if this algorithm is in the allowed list
		found := false
		for _, allowed := range allowedAlgorithms {
			if certAlg.Hash == allowed.Hash && certAlg.Signature == allowed.Signature {
				found = true

				break
			}
		}

		if !found {
			return dtlserrors.ErrInvalidCertificateSignatureAlgorithm
		}
	}

	return nil
}
