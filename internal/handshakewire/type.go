// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

// Package handshakewire provides shared handshake types and extension decoding.
package handshakewire

// Type is the unique identifier for each handshake message.
// https://www.rfc-editor.org/rfc/rfc9147#section-5.2
type Type uint8

// Types of DTLS 1.3 handshake messages we know about.
const (
	TypeClientHello         Type = 1
	TypeServerHello         Type = 2
	TypeNewSessionTicket    Type = 4
	TypeEncryptedExtensions Type = 8
	TypeRequestConnectionID Type = 9
	TypeNewConnectionID     Type = 10
	TypeCertificate         Type = 11
	TypeCertificateRequest  Type = 13
	TypeCertificateVerify   Type = 15
	TypeFinished            Type = 20
	TypeKeyUpdate           Type = 24

	// TypeMessageHash is a synthetic TLS 1.3 transcript-only handshake type.
	TypeMessageHash Type = 254
)

// String returns the string representation of this type.
func (t Type) String() string {
	switch t {
	case TypeClientHello:
		return "ClientHello"
	case TypeServerHello:
		return "ServerHello"
	case TypeCertificate:
		return "TypeCertificate"
	case TypeCertificateRequest:
		return "CertificateRequest"
	case TypeCertificateVerify:
		return "CertificateVerify"
	case TypeFinished:
		return "Finished"
	default:
		return t.postHelloName()
	}
}

func (t Type) postHelloName() string {
	switch t {
	case TypeNewSessionTicket:
		return "NewSessionTicket"
	case TypeEncryptedExtensions:
		return "EncryptedExtensions"
	case TypeRequestConnectionID:
		return "RequestConnectionID"
	case TypeNewConnectionID:
		return "NewConnectionID"
	case TypeKeyUpdate:
		return "KeyUpdate"
	case TypeMessageHash:
		return "MessageHash"
	default:
		return ""
	}
}
