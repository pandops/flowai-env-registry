package test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/pandops/flowai-env-registry/internal/outbox"
)

func b64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

// encodings returns the forms in which raw bytes could leak into text.
func encodings(b []byte) []string {
	return []string{
		base64.StdEncoding.EncodeToString(b),
		base64.RawStdEncoding.EncodeToString(b),
		base64.URLEncoding.EncodeToString(b),
		base64.RawURLEncoding.EncodeToString(b),
		hex.EncodeToString(b),
	}
}

// Fake mounted files the configuration references (deployment contract §1).
var testFiles = map[string]string{
	"/run/flowai/stand-ca/ca.pem": "-----BEGIN CERTIFICATE-----\nMIIBfake\n-----END CERTIFICATE-----\n",
	"/run/flowai/nats/user.creds": "-----BEGIN NATS USER JWT-----\neyJ0eXAiOiJKV1QiLCJhbGciOiJlZDI1NTE5LW5rZXkifQ.fake.sig\n------END NATS USER JWT------\n\n-----BEGIN USER NKEY SEED-----\nSUAFAKESEEDFAKESEEDFAKESEEDFAKESEEDFAKESEEDFAKESEEDFAKE\n------END USER NKEY SEED------\n",
}

func readTestFile(path string) ([]byte, error) {
	if v, ok := testFiles[path]; ok {
		return []byte(v), nil
	}
	return nil, fmt.Errorf("open %s: %w", path, os.ErrNotExist)
}

var testVerificationKey = ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x07}, 32)).Public().(ed25519.PublicKey)

// testDBPassword is the inline database password (the config file is a Secret).
const testDBPassword = "pg-password-not-logged"

// natsSection renders the nats section; creds is the credentials line(s).
func natsSection(url, creds string) string {
	return "nats:\n  url: " + url + "\n  ca_file: /run/flowai/stand-ca/ca.pem\n" + creds +
		"  inbox_prefix: _INBOX.env-registry\n  request_timeout: 5s\n"
}

// configSections are the sections of a valid production configuration,
// keyed as in the deployment contract §2 and §6.
func configSections() map[string]string {
	return map[string]string{
		"http": "http:\n  listen: \":8080\"\n",
		"db": "db:\n  host: postgres\n  port: 5432\n  user: env_registry\n  password: " + testDBPassword + "\n" +
			"  sslmode: verify-full\n  ca_file: /run/flowai/stand-ca/ca.pem\n",
		"nats":            natsSection("tls://nats:4222", "  credentials_file: /run/flowai/nats/user.creds\n"),
		"claim_token":     "claim_token:\n  verification_key: " + b64(testVerificationKey) + "\n",
		"encryption_keys": "encryption_keys:\n  - id: 1\n    key_hex: " + hex.EncodeToString(testDataKey) + "\n",
		"cursor_keys":     "cursor_keys:\n  - id: 1\n    key_hex: " + hex.EncodeToString(bytes.Repeat([]byte{0x11}, 32)) + "\n",
		"extra":           "",
	}
}

// validConfigYAML renders a valid configuration with some sections replaced.
func validConfigYAML(t testing.TB, overrides map[string]string) string {
	t.Helper()
	s := configSections()
	for k, v := range overrides {
		if _, ok := s[k]; !ok {
			t.Fatalf("unknown config section %q", k)
		}
		s[k] = v
	}
	var b strings.Builder
	for _, k := range []string{"http", "db", "nats", "claim_token", "encryption_keys", "cursor_keys", "extra"} {
		b.WriteString(s[k])
	}
	return b.String()
}

// flushAll relays every pending outbox row to the fake broker.
func flushAll(t *testing.T, e *env) {
	t.Helper()
	r := &outbox.Relay{Store: e.store, Publisher: e.broker, Logger: nil}
	for {
		n, err := r.Flush(context.Background())
		if err != nil {
			t.Fatalf("outbox flush: %v", err)
		}
		if n == 0 {
			return
		}
	}
}

// alwaysReady is a readiness check that always passes.
type alwaysReady struct{}

func (alwaysReady) Ready(context.Context) error { return nil }
