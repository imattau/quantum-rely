package main

import (
	"encoding/hex"
	"testing"
)

func TestNormalizeNpub(t *testing.T) {
	bytes := make([]byte, 32)
	for i := range bytes {
		bytes[i] = byte(i)
	}
	npub := encodeNpubForTest(bytes)
	got, err := normalizePubkey(npub)
	if err != nil {
		t.Fatal(err)
	}
	if got != hex.EncodeToString(bytes) {
		t.Fatalf("decoded pubkey = %s, want %s", got, hex.EncodeToString(bytes))
	}
}

func TestAuthorizedEvent(t *testing.T) {
	allowed := []string{"allowed"}
	if !authorizedEvent([]string{"allowed"}, allowed, "allowed") {
		t.Fatal("expected authenticated allowlisted author to be accepted")
	}
	if authorizedEvent([]string{"other"}, allowed, "allowed") {
		t.Fatal("expected event author to match an authenticated pubkey")
	}
	if authorizedEvent([]string{"allowed"}, allowed, "other") {
		t.Fatal("expected event author to be allowlisted")
	}
	if !authorizedEvent(nil, nil, "any") {
		t.Fatal("expected empty allowlist to preserve open mode")
	}
}

func encodeNpubForTest(data []byte) string {
	converted, err := convertBits(data, 8, 5, true)
	if err != nil {
		panic(err)
	}
	values := append([]byte{}, converted...)
	values = append(values, 0, 0, 0, 0, 0, 0)
	mod := bech32Polymod(append(bech32HRPExpand("npub"), values...)) ^ 1
	checksum := make([]byte, 6)
	for i := range checksum {
		checksum[i] = byte((mod >> uint(5*(5-i))) & 31)
	}
	values = append(converted, checksum...)
	out := "npub1"
	for _, value := range values {
		out += string(bech32Charset[value])
	}
	return out
}
