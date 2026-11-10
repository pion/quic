// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package dtls

import (
	"bytes"
	"crypto"
	"time"

	"github.com/pion/dtls/v4/internal/ciphersuite"
	dtlsstate "github.com/pion/dtls/v4/internal/state"
	"github.com/pion/dtls/v4/internal/util"
)

// SessionTicket contains the metadata needed to use a DTLS 1.3 ticket.
type SessionTicket = dtlsstate.SessionTicket

// Session store data needed in resumption.
type Session struct {
	// ID stores the DTLS 1.3 ticket identity.
	ID []byte
	// Secret stores the DTLS 1.3 resumption PSK.
	Secret []byte //nolint:gosec // Session stores intentionally retain the resumption secret.
	// Ticket holds the ticket metadata.
	Ticket *SessionTicket
	// IsClient binds the session to the endpoint role that authenticated it.
	IsClient bool
	// IdentityHint is the original external PSK identity, if any.
	IdentityHint []byte
}

// ticketPSK ignores expired tickets and sessions from other protocol versions or names.
func (s Session) ticketPSK(serverName string, now time.Time) *dtlsstate.PSK {
	ticket := s.Ticket
	if ticket == nil || ticket.ServerName != serverName || len(s.ID) == 0 {
		return nil
	}
	age := now.Sub(ticket.CreatedAt)
	if !validSessionTicketAge(age, ticket.Lifetime) {
		return nil
	}
	suite := ciphersuite.ForID(ticket.CipherSuite)
	if suite == nil || len(s.Secret) != suite.HashFunc()().Size() {
		return nil
	}
	hashID := crypto.SHA256
	if suite.HashFunc()().Size() == crypto.SHA384.Size() {
		hashID = crypto.SHA384
	}

	return &dtlsstate.PSK{
		Ticket: &SessionTicket{
			CipherSuite: ticket.CipherSuite, Lifetime: ticket.Lifetime, AgeAdd: ticket.AgeAdd,
			CreatedAt: ticket.CreatedAt, MaxEarlyDataSize: ticket.MaxEarlyDataSize, NegotiatedProtocol: ticket.NegotiatedProtocol,
		},
		Identity: bytes.Clone(s.ID), Secret: bytes.Clone(s.Secret), Hash: hashID,
		IdentityHint: bytes.Clone(s.IdentityHint),
		//nolint:gosec // Age is bounded to seven days, addition wraps modulo 2^32 https://datatracker.ietf.org/doc/html/rfc9846#section-4.3.11.1
		ObfuscatedTicketAge: uint32(age.Milliseconds()) + ticket.AgeAdd,
		PeerCertificates:    util.CloneByteSlices(ticket.PeerCertificates),
	}
}

func validSessionTicketAge(age time.Duration, lifetime uint32) bool {
	const maxLifetime = 7 * 24 * 60 * 60

	return age >= 0 && lifetime > 0 && lifetime <= maxLifetime && age < time.Duration(lifetime)*time.Second
}

// SessionStore defines methods needed for session resumption.
// Stores must preserve every Session field.
type SessionStore interface {
	// Set save a session.
	// For client, use server name as key.
	// For server, use the ticket identity.
	Set(key []byte, s Session) error
	// Get fetch a session.
	Get(key []byte) (Session, error)
}

// EarlyDataSessionStore optionally supports replay-protected early data.
// Claim atomically marks a ticket used for early data, returning true only once.
// Claims must be shared across all servers using the tickets and retained until
// expiresAt, even if the session is updated or deleted. Claim preserves the
// session for ordinary resumption. Errors reject early data, not resumption.
type EarlyDataSessionStore interface {
	SessionStore
	Claim(ticket []byte, expiresAt time.Time) (bool, error)
}
