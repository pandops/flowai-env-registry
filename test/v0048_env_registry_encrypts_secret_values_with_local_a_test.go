package test

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/pandops/flowai-env-registry/internal/mocks"
	"github.com/pandops/flowai-env-registry/internal/secretbox"
	"github.com/pandops/flowai-env-registry/internal/store"
)

// Requirement: env-registry encrypts secret values with local AES-256-GCM.
func TestEnvRegistryEncryptsSecretValuesWithLocalAESGCM(t *testing.T) {
	t.Run("Associated data binds team, secret and version", func(t *testing.T) {
		p, err := secretbox.NewLocal([]secretbox.Key{{ID: 1, Material: testDataKey}}, 1)
		if err != nil {
			t.Fatal(err)
		}
		aad := secretbox.AAD{TeamID: 3, SecretID: 7, Version: 2}
		env, err := p.Encrypt(aad, []byte(secretCanary))
		if err != nil {
			t.Fatal(err)
		}
		if len(env.Nonce) != 12 || len(env.Ciphertext) != len(secretCanary)+16 || env.KeyID != 1 || env.Provider != secretbox.ProviderLocal {
			t.Fatalf("envelope shape: nonce %d bytes, ciphertext %d bytes, key %d, provider %q", len(env.Nonce), len(env.Ciphertext), env.KeyID, env.Provider)
		}
		if pt, err := p.Decrypt(aad, env); err != nil || string(pt) != secretCanary {
			t.Fatalf("decrypt with matching data: %q %v", pt, err)
		}
		for _, other := range []secretbox.AAD{{TeamID: 4, SecretID: 7, Version: 2}, {TeamID: 3, SecretID: 8, Version: 2}, {TeamID: 3, SecretID: 7, Version: 1}} {
			if _, err := p.Decrypt(other, env); !errors.Is(err, secretbox.ErrDecrypt) {
				t.Errorf("decrypt with %+v: %v, want ErrDecrypt", other, err)
			}
		}
		tampered := env
		tampered.Ciphertext = append([]byte(nil), env.Ciphertext...)
		tampered.Ciphertext[len(tampered.Ciphertext)-1] ^= 1
		if _, err := p.Decrypt(aad, tampered); !errors.Is(err, secretbox.ErrDecrypt) {
			t.Errorf("tampered tag: %v", err)
		}
		badNonce := env
		badNonce.Nonce = env.Nonce[:8]
		if _, err := p.Decrypt(aad, badNonce); !errors.Is(err, secretbox.ErrDecrypt) {
			t.Errorf("short nonce: %v", err)
		}
		unknownKey := env
		unknownKey.KeyID = 2
		if _, err := p.Decrypt(aad, unknownKey); err == nil {
			t.Error("key_id outside the configured window decrypted")
		}
		second, _ := p.Encrypt(aad, []byte(secretCanary))
		if bytes.Equal(second.Nonce, env.Nonce) {
			t.Error("nonce reused")
		}
		// The service binds the canonical record: a version moved to another
		// secret of the same team does not open.
		e := newEnv(t)
		id := e.createTeam(3, "base", map[string]string{})
		a := e.createSecret(3, id, "A", secretCanary)
		b := e.createSecret(3, id, "B", secretCanary2)
		err = e.store.InTx(context.Background(), func(tx store.Tx) error {
			va, err := tx.GetSecretVersion(context.Background(), 3, a, 1)
			if err != nil {
				return err
			}
			sb, err := tx.GetSecret(context.Background(), 3, b)
			if err != nil {
				return err
			}
			va.SecretID = b
			va.Version = 2
			if err := tx.InsertSecretVersion(context.Background(), va); err != nil {
				return err
			}
			sb.LatestVersion = 2
			return tx.UpdateSecret(context.Background(), sb)
		})
		if err != nil {
			t.Fatal(err)
		}
		c := claim(5, 1, 1)
		e.setClaim(c, 1, true)
		r := e.open("5", e.token(c))
		if r.Status != 503 || openCode(t, r) != "service_unavailable" || strings.Contains(string(r.Body), secretCanary) {
			t.Fatalf("moved version opened: %d %s", r.Status, r.Body)
		}
	})

	t.Run("Missing data key fails closed", func(t *testing.T) {
		// The provider refuses to build without a usable key.
		if _, err := secretbox.NewLocal(nil, 1); err == nil {
			t.Error("provider without keys built")
		}
		if _, err := secretbox.NewLocal([]secretbox.Key{{ID: 1, Material: testDataKey}}, 2); err == nil {
			t.Error("provider with an unknown active key built")
		}
		// Runtime: the provider fails; nothing is encrypted, decrypted or returned.
		e := newEnv(t)
		id := e.createTeam(3, "base", map[string]string{"A": "1"})
		e.createSecret(3, id, "DB_PASSWORD", secretCanary)
		broken := newEnv(t, withProvider(mocks.FailingProvider{Err: secretbox.ErrUnavailable}))
		bid := broken.createTeam(3, "base", map[string]string{"A": "1"})
		w := broken.ui("create-secret", 3, map[string]any{"team_id": 3, "environment_id": bid}, map[string]any{"key": "DB_PASSWORD", "value": secretCanary})
		if w.Status != 503 || w.code() != "service_unavailable" || len(broken.store.Secrets()) != 0 {
			t.Fatalf("secret write without key: %d %s", w.Status, w.Raw)
		}
		// Seed a version with the working provider, then open without a key.
		var version store.SecretVersion
		_ = e.store.InTx(context.Background(), func(tx store.Tx) error {
			var err error
			version, err = tx.GetSecretVersion(context.Background(), 3, 1, 1)
			return err
		})
		_ = broken.store.InTx(context.Background(), func(tx store.Tx) error {
			if err := tx.InsertSecret(context.Background(), store.Secret{TeamID: 3, SecretID: 1, EnvironmentID: bid, Key: "DB_PASSWORD", LatestVersion: 1}); err != nil {
				return err
			}
			return tx.InsertSecretVersion(context.Background(), version)
		})
		c := claim(9, 1, 1)
		broken.setClaim(c, 1, true)
		r := broken.open("9", broken.token(c))
		if r.Status != 503 || openCode(t, r) != "service_unavailable" || strings.Contains(string(r.Body), "\"A\"") {
			t.Fatalf("open without key: %d %s", r.Status, r.Body)
		}
		nokey := newEnv(t, withProvider(nil))
		nid := nokey.createTeam(3, "base", map[string]string{"A": "1"})
		if w := nokey.ui("create-secret", 3, map[string]any{"team_id": 3, "environment_id": nid}, map[string]any{"key": "K", "value": "v"}); w.Status != 503 {
			t.Fatalf("secret write with no provider: %d", w.Status)
		}
		c2 := claim(10, 1, 1)
		nokey.setClaim(c2, 1, true)
		if r := nokey.open("10", nokey.token(c2)); r.Status != 503 {
			t.Fatalf("open with no provider: %d %s", r.Status, r.Body)
		}
	})

	t.Run("No secret material in logs or events", func(t *testing.T) {
		e := newEnv(t)
		id := e.createTeam(3, "base", map[string]string{})
		sid := e.createSecret(3, id, "DB_PASSWORD", secretCanary)
		e.ui("replace-secret", 3, map[string]any{"team_id": 3, "environment_id": id, "secret_id": sid}, map[string]any{"value": secretCanary2})
		e.ui("create-secret", 3, map[string]any{"team_id": 3, "environment_id": id}, map[string]any{"key": "OPENAI_API_KEY", "value": secretCanary})
		e.ui("create-secret", 4, map[string]any{"team_id": 4, "environment_id": id}, map[string]any{"key": "X", "value": secretCanary})
		c := claim(1, 1, 1)
		e.setClaim(c, 1, true)
		ok := e.open("1", e.token(c))
		if ok.Status != 200 {
			t.Fatalf("open %d", ok.Status)
		}
		e.setClaim(c, 1, false)
		refused := e.open("1", e.token(c))
		if strings.Contains(string(refused.Body), secretCanary2) {
			t.Fatal("refused open returns a value")
		}
		v := e.store.Versions()
		material := [][]byte{testDataKey}
		for _, ver := range v {
			material = append(material, ver.Envelope.Nonce, ver.Envelope.Ciphertext, ver.Envelope.Ciphertext[len(ver.Envelope.Ciphertext)-16:])
		}
		logs := e.logs.String()
		for _, m := range material {
			for _, enc := range encodings(m) {
				if strings.Contains(logs, enc) {
					t.Fatalf("log contains key, nonce, ciphertext or tag bytes")
				}
				for _, row := range e.store.Outbox() {
					if bytes.Contains(row.Payload, []byte(enc)) {
						t.Fatalf("%s contains key, nonce, ciphertext or tag bytes", row.Subject)
					}
				}
				if strings.Contains(string(refused.Body), enc) {
					t.Fatal("error response contains secret material")
				}
			}
		}
		e.assertNoCanary(t, secretCanary, secretCanary2)
	})
}
