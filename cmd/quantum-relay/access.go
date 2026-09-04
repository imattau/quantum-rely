package main

import (
	"encoding/hex"
	"fmt"
	"strings"
)

// normalizeAllowedPubkeys converts administrator-facing npubs to the hex
// representation used by Nostr events and NIP-42 authentication. Hex keys
// remain accepted for compatibility with existing tooling.
func normalizeAllowedPubkeys(cfg *AuthConfig) error {
	seen := make(map[string]struct{}, len(cfg.AllowedPubkeys))
	keys := make([]string, 0, len(cfg.AllowedPubkeys))
	for _, raw := range cfg.AllowedPubkeys {
		key, err := normalizePubkey(raw)
		if err != nil {
			return fmt.Errorf("invalid auth.allowed_pubkeys entry %q: %w", raw, err)
		}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		keys = append(keys, key)
	}
	cfg.AllowedPubkeys = keys
	if len(keys) > 0 {
		cfg.Required = true
	}
	return nil
}

func normalizePubkey(raw string) (string, error) {
	raw = strings.ToLower(strings.TrimSpace(raw))
	if len(raw) == 64 {
		if _, err := hex.DecodeString(raw); err != nil {
			return "", fmt.Errorf("expected a 64-character hex pubkey or npub")
		}
		return raw, nil
	}
	hrp, data, err := bech32Decode(raw)
	if err != nil || hrp != "npub" {
		return "", fmt.Errorf("expected a valid npub or 64-character hex pubkey")
	}
	decoded, err := convertBits(data, 5, 8, false)
	if err != nil || len(decoded) != 32 {
		return "", fmt.Errorf("npub payload must contain exactly 32 bytes")
	}
	return hex.EncodeToString(decoded), nil
}

const bech32Charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

func bech32Decode(value string) (string, []byte, error) {
	if value == strings.ToUpper(value) || value != strings.ToLower(value) {
		return "", nil, fmt.Errorf("mixed-case bech32 value")
	}
	sep := strings.LastIndexByte(value, '1')
	if sep < 1 || sep+7 > len(value) || len(value) > bech32MaxLength {
		return "", nil, fmt.Errorf("invalid bech32 length")
	}
	values := make([]byte, len(value)-sep-1)
	for i, r := range value[sep+1:] {
		idx := strings.IndexRune(bech32Charset, r)
		if idx < 0 {
			return "", nil, fmt.Errorf("invalid bech32 character")
		}
		values[i] = byte(idx)
	}
	if bech32Polymod(append(bech32HRPExpand(value[:sep]), values...)) != 1 {
		return "", nil, fmt.Errorf("invalid bech32 checksum")
	}
	return value[:sep], values[:len(values)-6], nil
}

const bech32MaxLength = 90

func bech32HRPExpand(hrp string) []byte {
	result := make([]byte, 0, len(hrp)*2+1)
	for _, r := range hrp {
		result = append(result, byte(r)>>5)
	}
	result = append(result, 0)
	for _, r := range hrp {
		result = append(result, byte(r)&31)
	}
	return result
}

func bech32Polymod(values []byte) uint32 {
	const generator0 = 0x3b6a57b2
	const generator1 = 0x26508e6d
	const generator2 = 0x1ea119fa
	const generator3 = 0x3d4233dd
	const generator4 = 0x2a1462b3
	chk := uint32(1)
	for _, value := range values {
		top := chk >> 25
		chk = (chk&0x1ffffff)<<5 ^ uint32(value)
		if top&1 != 0 {
			chk ^= generator0
		}
		if top&2 != 0 {
			chk ^= generator1
		}
		if top&4 != 0 {
			chk ^= generator2
		}
		if top&8 != 0 {
			chk ^= generator3
		}
		if top&16 != 0 {
			chk ^= generator4
		}
	}
	return chk
}

func convertBits(data []byte, from, to uint, pad bool) ([]byte, error) {
	var acc uint
	var bits uint
	result := make([]byte, 0, len(data)*int(from)/int(to))
	max := uint32((1 << to) - 1)
	for _, value := range data {
		if uint(value)>>from != 0 {
			return nil, fmt.Errorf("invalid bit group")
		}
		acc = acc<<from | uint(value)
		bits += from
		for bits >= to {
			bits -= to
			result = append(result, byte((acc>>bits)&uint(max)))
		}
	}
	if pad {
		if bits > 0 {
			result = append(result, byte((acc<<(to-bits))&uint(max)))
		}
	} else if bits >= from || ((acc<<(to-bits))&uint(max)) != 0 {
		return nil, fmt.Errorf("invalid padding")
	}
	return result, nil
}

func allowedPubkey(keys []string, pubkey string) bool {
	for _, key := range keys {
		if key == pubkey {
			return true
		}
	}
	return false
}

// authorizedEvent requires both an allowlisted event author and proof that
// the same key authenticated the client. Keeping this decision in one place
// leaves room for adding paid entitlements without weakening event signing
// checks.
func authorizedEvent(authenticated, allowed []string, eventPubkey string) bool {
	if len(allowed) == 0 {
		return true
	}
	return allowedPubkey(allowed, eventPubkey) && allowedPubkey(authenticated, eventPubkey)
}
