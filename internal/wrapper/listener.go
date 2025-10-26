// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package wrapper

import (
	"context"

	quic "github.com/quic-go/quic-go"
)

// A Listener for incoming QUIC connections.
type Listener struct {
	l *quic.Listener
}

// Accept accepts incoming streams.
func (l *Listener) Accept() (*Conn, error) {
	c, err := l.l.Accept(context.TODO())
	if err != nil {
		return nil, err
	}

	return &Conn{c: c}, nil
}

// Close closes the listener.
func (l *Listener) Close() error {
	return l.l.Close()
}
