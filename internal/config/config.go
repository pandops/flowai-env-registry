// Package config loads env-registry's YAML configuration
// (deployment contract §2 and §6). Unknown keys fail startup.
package config

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/pandops/flowai-env-registry/internal/cursor"
	"github.com/pandops/flowai-env-registry/internal/secretbox"
)

// Database is the platform database every service schema lives in.
const Database = "flowai"

// DefaultSchema is env-registry's PostgreSQL schema.
const DefaultSchema = "env_registry_schema"

var schemaPattern = regexp.MustCompile(`^[a-z][a-z0-9_]{0,55}_schema$`)

// DB is the PostgreSQL connection.
type DB struct {
	Host     string
	Port     int
	User     string
	Password string
	Schema   string
	Database string
	SSLMode  string
	CAFile   string
}

// NATS is the broker connection.
type NATS struct {
	URL            string
	CAFile         string
	CredsFile      string // nats.credentials_file
	InboxPrefix    string // nats.inbox_prefix
	RequestTimeout time.Duration
}

// Config is the resolved configuration.
type Config struct {
	HTTPBind        string
	DB              DB
	NATS            NATS
	VerificationKey ed25519.PublicKey
	EncryptionKeys  []secretbox.Key // encryption_keys; the highest id encrypts
	ActiveKeyID     int64
	CursorKeys      []cursor.Key // cursor_keys; the highest id signs
	ActiveCursorKey int64
}

type keyEntry struct {
	ID     *int64 `yaml:"id"`
	KeyHex string `yaml:"key_hex"`
}

type file struct {
	HTTP struct {
		Listen string `yaml:"listen"`
	} `yaml:"http"`
	DB struct {
		Host     string `yaml:"host"`
		Port     int    `yaml:"port"`
		User     string `yaml:"user"`
		Password string `yaml:"password"`
		Schema   string `yaml:"schema"`
		SSLMode  string `yaml:"sslmode"`
		CAFile   string `yaml:"ca_file"`
	} `yaml:"db"`
	NATS struct {
		URL             string `yaml:"url"`
		CAFile          string `yaml:"ca_file"`
		CredentialsFile string `yaml:"credentials_file"`
		InboxPrefix     string `yaml:"inbox_prefix"`
		RequestTimeout  string `yaml:"request_timeout"`
	} `yaml:"nats"`
	ClaimToken struct {
		VerificationKey string `yaml:"verification_key"`
	} `yaml:"claim_token"`
	EncryptionKeys []keyEntry `yaml:"encryption_keys"`
	CursorKeys     []keyEntry `yaml:"cursor_keys"`
}

// Load reads and validates the YAML file at path.
func Load(path string) (Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, err
	}
	return Parse(data, os.ReadFile)
}

// Parse validates YAML content; readFile reads referenced files.
func Parse(data []byte, readFile func(string) ([]byte, error)) (Config, error) {
	var f file
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&f); err != nil {
		return Config{}, fmt.Errorf("config: %w", err)
	}
	var errs []error
	fail := func(format string, a ...any) { errs = append(errs, fmt.Errorf("config: "+format, a...)) }

	c := Config{HTTPBind: f.HTTP.Listen}
	if c.HTTPBind == "" {
		c.HTTPBind = ":8080"
	}

	c.DB = DB{Host: f.DB.Host, Port: f.DB.Port, User: f.DB.User, Password: f.DB.Password, Schema: f.DB.Schema,
		Database: Database, SSLMode: f.DB.SSLMode, CAFile: f.DB.CAFile}
	if c.DB.Schema == "" {
		c.DB.Schema = DefaultSchema
	}
	if c.DB.Port == 0 {
		c.DB.Port = 5432
	}
	switch {
	case c.DB.Host == "" || c.DB.User == "" || c.DB.Password == "":
		fail("db.host, db.user and db.password are required")
	case c.DB.SSLMode != "verify-full":
		fail("db.sslmode must be verify-full")
	case c.DB.CAFile == "":
		fail("db.ca_file is required")
	case !schemaPattern.MatchString(c.DB.Schema):
		fail("db.schema %q is not a service schema name", c.DB.Schema)
	}
	if c.DB.CAFile != "" {
		if _, err := readFile(c.DB.CAFile); err != nil {
			fail("db.ca_file: %v", err)
		}
	}

	c.NATS = NATS{URL: f.NATS.URL, CAFile: f.NATS.CAFile, CredsFile: f.NATS.CredentialsFile, InboxPrefix: f.NATS.InboxPrefix}
	if u, err := url.Parse(c.NATS.URL); err != nil || u.Scheme != "tls" || u.Host == "" {
		fail("nats.url must be a tls:// URL")
	}
	if c.NATS.CAFile == "" {
		fail("nats.ca_file is required")
	} else if _, err := readFile(c.NATS.CAFile); err != nil {
		fail("nats.ca_file: %v", err)
	}
	if c.NATS.CredsFile == "" {
		fail("nats.credentials_file is required")
	} else if creds, err := readFile(c.NATS.CredsFile); err != nil {
		fail("nats.credentials_file: %v", err)
	} else if !strings.Contains(string(creds), "BEGIN NATS USER JWT") || !strings.Contains(string(creds), "BEGIN USER NKEY SEED") {
		fail("nats.credentials_file must hold a user JWT and its seed")
	}
	if c.NATS.InboxPrefix == "" {
		c.NATS.InboxPrefix = "_INBOX.env-registry"
	}
	c.NATS.RequestTimeout = 5 * time.Second
	if f.NATS.RequestTimeout != "" {
		d, err := time.ParseDuration(f.NATS.RequestTimeout)
		if err != nil || d <= 0 {
			fail("nats.request_timeout: invalid duration")
		}
		c.NATS.RequestTimeout = d
	}

	if k, err := base64.StdEncoding.DecodeString(f.ClaimToken.VerificationKey); err != nil || len(k) != ed25519.PublicKeySize {
		fail("claim_token.verification_key must be a base64 Ed25519 public key")
	} else {
		c.VerificationKey = ed25519.PublicKey(k)
	}

	enc, active, err := parseKeys("encryption_keys", f.EncryptionKeys, true)
	if err != nil {
		errs = append(errs, err)
	}
	for _, k := range enc {
		c.EncryptionKeys = append(c.EncryptionKeys, secretbox.Key{ID: k.id, Material: k.material})
	}
	c.ActiveKeyID = active
	cur, activeCursor, err := parseKeys("cursor_keys", f.CursorKeys, false)
	if err != nil {
		errs = append(errs, err)
	}
	for _, k := range cur {
		c.CursorKeys = append(c.CursorKeys, cursor.Key{ID: k.id, Secret: k.material})
	}
	c.ActiveCursorKey = activeCursor
	if len(errs) > 0 {
		return Config{}, errors.Join(errs...)
	}
	return c, nil
}

type parsedKey struct {
	id       int64
	material []byte
}

func parseKeys(name string, entries []keyEntry, exact32 bool) ([]parsedKey, int64, error) {
	if len(entries) == 0 {
		return nil, 0, fmt.Errorf("config: %s needs at least one key", name)
	}
	var out []parsedKey
	var active int64
	seen := map[int64]bool{}
	for _, e := range entries {
		if e.ID == nil || *e.ID < 1 || seen[*e.ID] {
			return nil, 0, fmt.Errorf("config: %s ids must be distinct positive integers", name)
		}
		seen[*e.ID] = true
		m, err := hex.DecodeString(e.KeyHex)
		if err != nil || (exact32 && len(m) != 32) || len(m) < 32 {
			return nil, 0, fmt.Errorf("config: %s key %d must be 32 bytes of hex", name, *e.ID)
		}
		out = append(out, parsedKey{id: *e.ID, material: m})
		active = max(active, *e.ID)
	}
	return out, active, nil
}

// DSN is the pgx connection string, with search_path set to the schema.
// The password is quoted and never logged.
func (d DB) DSN() string {
	q := func(v string) string { return "'" + strings.NewReplacer(`\`, `\\`, `'`, `\'`).Replace(v) + "'" }
	return fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=%s sslrootcert=%s search_path=%s",
		d.Host, d.Port, d.User, q(d.Password), d.Database, d.SSLMode, d.CAFile, d.Schema)
}
