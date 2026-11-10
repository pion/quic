// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

// Package flight contains shared internal flight state and helpers.
package flight

import (
	"bytes"
	"fmt"
	"slices"
	"sync"

	dtlserrors "github.com/pion/dtls/v4/internal/errors"
	"github.com/pion/dtls/v4/internal/protocol/alert"
	"github.com/pion/dtls/v4/internal/protocol/handshake"
)

type Cache struct {
	size  int
	cache []*HandshakeCacheItem
	mu    sync.Mutex
}

type handshakeCacheDecodeKind uint8

const (
	handshakeCacheDecodeGeneric handshakeCacheDecodeKind = iota
	handshakeCacheDecodeProtected13
)

type handshakeCacheDecodeContext struct {
	kind handshakeCacheDecodeKind
}

// HandshakeCacheDecoder decodes a complete cached handshake message.
type HandshakeCacheDecoder func([]byte) (*handshake.Handshake, error)

func NewCache() *Cache {
	return &Cache{}
}

func (h *Cache) Push(data []byte, epoch uint64, messageSequence uint16, typ handshake.Type, isClient bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.cache = append(h.cache, &HandshakeCacheItem{Data: bytes.Clone(data), Epoch: epoch, MessageSequence: messageSequence, Typ: typ, IsClient: isClient})
	h.size += len(data)
}

func (h *Cache) DiscardBefore(epoch uint64, sequence int, isClient bool) {
	if h == nil {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	retained := h.cache[:0]
	h.size = 0
	for _, item := range h.cache {
		if item.Epoch < epoch || (item.IsClient == isClient && int(item.MessageSequence) < sequence) {
			continue
		}
		retained = append(retained, item)
		h.size += len(item.Data)
	}
	clear(h.cache[len(retained):])
	h.cache = retained
}

// PullExact returns the handshake message with the requested sequence and
// sender.
func (h *Cache) PullExact(messageSequence uint16, isClient bool) (*HandshakeCacheItem, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()

	for _, item := range h.cache {
		if item.MessageSequence == messageSequence && item.IsClient == isClient {
			return item, true
		}
	}

	return nil, false
}

// Pull returns a list handshakes that match the requested rules.
// The list will contain null entries for rules that can't be satisfied.
// Multiple entries may match a rule, but only the last match is returned (ie ClientHello with cookies).
func (h *Cache) Pull(rules ...HandshakeCachePullRule) []*HandshakeCacheItem {
	h.mu.Lock()
	defer h.mu.Unlock()

	out := make([]*HandshakeCacheItem, len(rules))
	for i, r := range rules {
		for _, c := range h.cache {
			if c.Typ == r.Typ && c.IsClient == r.IsClient && c.Epoch == r.Epoch {
				switch {
				case out[i] == nil:
					out[i] = c
				case out[i].MessageSequence < c.MessageSequence:
					out[i] = c
				}
			}
		}
	}

	return out
}

func (h *Cache) FullPullMapItems(startSeq int, rules ...HandshakeCachePullRule) HandshakeCachePullResult {
	selection := h.PullSequential(startSeq, rules...)
	if selection.Err != nil || !selection.Ready {
		return HandshakeCachePullResult{
			NextSequence: startSeq,
			Ready:        selection.Ready,
			Err:          selection.Err,
		}
	}

	return h.fullPullMapCacheItems(startSeq, rules, selection.Items)
}

func validHandshakeSequence(sequence int) bool {
	return sequence >= 0 && sequence <= int(^uint16(0))
}

// PullSequential selects messages at consecutive sequence numbers. Missing
// messages are incomplete.
func (h *Cache) PullSequential(
	startSeq int,
	rules ...HandshakeCachePullRule,
) HandshakeCacheItemPullResult {
	h.mu.Lock()
	defer h.mu.Unlock()

	items := make([]*HandshakeCacheItem, len(rules))
	seq := startSeq
	for i, rule := range rules {
		if !validHandshakeSequence(seq) {
			return HandshakeCacheItemPullResult{NextSequence: startSeq, Ready: true, Err: fmt.Errorf("%w: %w", dtlserrors.ErrHandshakeSequenceOverflow, &alert.Alert{Level: alert.Fatal, Description: alert.DecodeError})}
		}

		var conflicts []*HandshakeCacheItem
		items[i], conflicts = h.sequentialCandidates(seq, rule)

		if items[i] == nil {
			if rule.Optional {
				if slices.ContainsFunc(conflicts, func(conflict *HandshakeCacheItem) bool {
					return !matchesAnyHandshakePullRule(conflict, rules[i+1:])
				}) {
					return unexpectedHandshakePull(startSeq)
				}

				continue
			}
			if len(conflicts) != 0 {
				return unexpectedHandshakePull(startSeq)
			}

			return HandshakeCacheItemPullResult{NextSequence: startSeq}
		}
		if len(conflicts) != 0 {
			return unexpectedHandshakePull(startSeq)
		}

		seq++
	}
	if seq == startSeq {
		return HandshakeCacheItemPullResult{NextSequence: startSeq}
	}

	return HandshakeCacheItemPullResult{
		NextSequence: seq,
		Items:        items,
		Ready:        true,
	}
}

func (h *Cache) sequentialCandidates(seq int, rule HandshakeCachePullRule) (selected *HandshakeCacheItem, conflicts []*HandshakeCacheItem) {
	conflicts = make([]*HandshakeCacheItem, 0, 1)
	for _, item := range h.cache {
		if item.IsClient != rule.IsClient || item.Epoch != rule.Epoch ||
			item.MessageSequence != uint16(seq) { //nolint:gosec // seq is bounded above.
			continue
		}
		if item.Typ == rule.Typ {
			selected = item
		} else {
			conflicts = append(conflicts, item)
		}
	}

	return selected, conflicts
}

func matchesAnyHandshakePullRule(item *HandshakeCacheItem, rules []HandshakeCachePullRule) bool {
	return slices.ContainsFunc(rules, func(rule HandshakeCachePullRule) bool {
		return item.Typ == rule.Typ && item.IsClient == rule.IsClient && item.Epoch == rule.Epoch
	})
}

func unexpectedHandshakePull(startSeq int) HandshakeCacheItemPullResult {
	return HandshakeCacheItemPullResult{NextSequence: startSeq, Ready: true, Err: fmt.Errorf("%w: %w", dtlserrors.ErrUnexpectedHandshakeMessage, &alert.Alert{Level: alert.Fatal, Description: alert.UnexpectedMessage})}
}

func (h *Cache) fullPullMapCacheItems(startSeq int, rules []HandshakeCachePullRule, ci []*HandshakeCacheItem) HandshakeCachePullResult {
	out := make(map[handshake.Type]handshake.Message)
	items := make([]DecodedHandshakeCacheItem, 0, len(rules))
	seq := startSeq
	for i, r := range rules {
		typ := r.Typ
		item := ci[i]
		if item == nil {
			continue
		}
		parsed, err := h.decodeGenericHandshakeItem(
			item, r.Typ, uint16(seq), //nolint:gosec // selection bounded seq above.
		)
		if err != nil {
			return HandshakeCachePullResult{NextSequence: startSeq, Ready: true, Err: fmt.Errorf("%w: %w", err, &alert.Alert{Level: alert.Fatal, Description: alert.DecodeError})}
		}
		seq++
		out[typ] = parsed.Message
		items = append(items, DecodedHandshakeCacheItem{Raw: item, Parsed: parsed})
	}
	if len(items) == 0 {
		return HandshakeCachePullResult{NextSequence: seq}
	}

	return HandshakeCachePullResult{
		NextSequence: seq,
		Messages:     out,
		Items:        items,
		Ready:        true,
	}
}

func (h *Cache) decodeGenericHandshakeItem(item *HandshakeCacheItem, expectedType handshake.Type, expectedSequence uint16) (*handshake.Handshake, error) {
	context := handshakeCacheDecodeContext{kind: handshakeCacheDecodeGeneric}

	return h.decodeHandshakeItem(
		item,
		expectedType,
		expectedSequence,
		context,
		func(data []byte) (*handshake.Handshake, error) {
			parsed := &handshake.Handshake{}
			if err := parsed.Unmarshal(data); err != nil {
				return nil, err
			}

			return parsed, nil
		},
	)
}

// DecodeProtectedHandshakeItem decodes and retains one DTLS 1.3 protected
// handshake message, or returns the retained value by an earlier pull.
func (h *Cache) DecodeProtectedHandshakeItem(item *HandshakeCacheItem, expectedType handshake.Type, expectedSequence uint16, decoder HandshakeCacheDecoder) (*handshake.Handshake, error) {
	parsed, err := h.decodeHandshakeItem(item, expectedType, expectedSequence, handshakeCacheDecodeContext{kind: handshakeCacheDecodeProtected13}, decoder)
	if err != nil {
		return nil, fmt.Errorf(
			"%w: %w",
			err,
			&alert.Alert{Level: alert.Fatal, Description: alert.DecodeError},
		)
	}

	return parsed, nil
}

func (h *Cache) decodeHandshakeItem(item *HandshakeCacheItem, expectedType handshake.Type, expectedSequence uint16, context handshakeCacheDecodeContext, decoder HandshakeCacheDecoder) (*handshake.Handshake, error) {
	h.mu.Lock()
	defer h.mu.Unlock()

	if item == nil || decoder == nil || item.Typ != expectedType || item.MessageSequence != expectedSequence {
		return nil, dtlserrors.ErrInvalidHandshakeTranscriptMessage
	}
	if item.hasDecoded {
		if item.decodeContext != context {
			return nil, dtlserrors.ErrInvalidHandshakeTranscriptMessage
		}
		if err := validateDecodedHandshake(item, item.parsed); err != nil {
			return nil, err
		}

		return item.parsed, nil
	}

	parsed, err := decoder(item.Data)
	if err != nil {
		return nil, err
	}
	if err := validateDecodedHandshake(item, parsed); err != nil {
		return nil, err
	}

	item.parsed = parsed
	item.decodeContext = context
	item.hasDecoded = true

	return parsed, nil
}

// Validate checks that the raw and parsed views identify the same complete
// handshake message.
func (i DecodedHandshakeCacheItem) Validate() error {
	if err := validateDecodedHandshake(i.Raw, i.Parsed); err != nil {
		return err
	}
	if i.Raw.hasDecoded && i.Raw.parsed != i.Parsed {
		return dtlserrors.ErrInvalidHandshakeTranscriptMessage
	}

	return nil
}

func validateDecodedHandshake(
	item *HandshakeCacheItem,
	parsed *handshake.Handshake,
) error {
	if item == nil || parsed == nil || parsed.Message == nil {
		return dtlserrors.ErrInvalidHandshakeTranscriptMessage
	}

	var rawHeader handshake.Header
	if err := rawHeader.Unmarshal(item.Data); err != nil {
		return err
	}

	expected := handshake.Header{Type: item.Typ, Length: rawHeader.Length, MessageSequence: item.MessageSequence, FragmentLength: rawHeader.Length}
	if rawHeader != parsed.Header || rawHeader != expected || len(item.Data) != handshake.HeaderLength+int(rawHeader.Length) || parsed.Message.Type() != rawHeader.Type {
		return dtlserrors.ErrInvalidHandshakeTranscriptMessage
	}

	return nil
}

// PullAndMerge calls pull and then merges the results, ignoring any null entries.
func (h *Cache) PullAndMerge(rules ...HandshakeCachePullRule) []byte {
	merged := []byte{}

	for _, p := range h.Pull(rules...) {
		if p != nil {
			merged = append(merged, p.Data...)
		}
	}

	return merged
}
