-- env-registry's own schema. {{schema}} is replaced by the configured schema
-- name; no other schema is ever named.

CREATE SEQUENCE {{schema}}.publisher_seq AS bigint MINVALUE 1 NO CYCLE;

CREATE SEQUENCE {{schema}}.global_environment_seq AS bigint MINVALUE 1 NO CYCLE;

CREATE TABLE {{schema}}.team_counters (
    team_id bigint NOT NULL CHECK (team_id >= 1),
    kind text NOT NULL CHECK (kind IN ('environment', 'secret')),
    last_value bigint NOT NULL CHECK (last_value >= 1),
    PRIMARY KEY (team_id, kind)
);

-- team_id 0 holds global definitions, which no operator can read or write.
CREATE TABLE {{schema}}.definitions (
    team_id bigint NOT NULL CHECK (team_id >= 0),
    environment_id bigint NOT NULL CHECK (environment_id >= 1),
    scope text NOT NULL CHECK (scope IN ('global', 'team', 'flow')),
    flow_id bigint CHECK (flow_id >= 1),
    name text NOT NULL,
    env jsonb NOT NULL,
    revision integer NOT NULL CHECK (revision >= 1),
    deleted boolean NOT NULL DEFAULT false,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    PRIMARY KEY (team_id, environment_id),
    CHECK ((scope = 'global') = (team_id = 0)),
    CHECK ((scope = 'flow') = (flow_id IS NOT NULL))
);

CREATE UNIQUE INDEX definitions_active_team ON {{schema}}.definitions (team_id) WHERE scope = 'team' AND NOT deleted;

CREATE UNIQUE INDEX definitions_active_flow ON {{schema}}.definitions (team_id, flow_id) WHERE scope = 'flow' AND NOT deleted;

CREATE TABLE {{schema}}.secrets (
    team_id bigint NOT NULL CHECK (team_id >= 0),
    secret_id bigint NOT NULL CHECK (secret_id >= 1),
    environment_id bigint NOT NULL,
    key text NOT NULL,
    latest_version integer NOT NULL CHECK (latest_version >= 0),
    revoked boolean NOT NULL DEFAULT false,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    PRIMARY KEY (team_id, secret_id),
    FOREIGN KEY (team_id, environment_id) REFERENCES {{schema}}.definitions (team_id, environment_id)
);

CREATE UNIQUE INDEX secrets_active_key ON {{schema}}.secrets (team_id, environment_id, key) WHERE NOT revoked;

CREATE TABLE {{schema}}.secret_versions (
    team_id bigint NOT NULL,
    secret_id bigint NOT NULL,
    version integer NOT NULL CHECK (version >= 1),
    provider text NOT NULL,
    key_id bigint NOT NULL CHECK (key_id >= 1),
    nonce bytea NOT NULL,
    ciphertext bytea NOT NULL,
    created_at timestamptz NOT NULL,
    PRIMARY KEY (team_id, secret_id, version),
    FOREIGN KEY (team_id, secret_id) REFERENCES {{schema}}.secrets (team_id, secret_id)
);

CREATE TABLE {{schema}}.revisions (
    team_id bigint NOT NULL,
    environment_id bigint NOT NULL,
    revision integer NOT NULL CHECK (revision >= 1),
    scope text NOT NULL,
    flow_id bigint,
    name text NOT NULL,
    env jsonb NOT NULL,
    secret_keys jsonb NOT NULL,
    deleted boolean NOT NULL,
    actor_id bigint NOT NULL,
    request_id bigint NOT NULL,
    created_at timestamptz NOT NULL,
    PRIMARY KEY (team_id, environment_id, revision),
    FOREIGN KEY (team_id, environment_id) REFERENCES {{schema}}.definitions (team_id, environment_id)
);

-- Frozen per-attempt resolution: ordinary values and secret version references only.
CREATE TABLE {{schema}}.snapshots (
    team_id bigint NOT NULL CHECK (team_id >= 1),
    task_id bigint NOT NULL CHECK (task_id >= 1),
    attempt bigint NOT NULL CHECK (attempt >= 1),
    env_values jsonb NOT NULL,
    secret_refs jsonb NOT NULL,
    created_at timestamptz NOT NULL,
    PRIMARY KEY (team_id, task_id, attempt)
);

CREATE TABLE {{schema}}.consumed_messages (
    publisher text NOT NULL,
    publisher_seq bigint NOT NULL,
    consumed_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (publisher, publisher_seq)
);

CREATE TABLE {{schema}}.outbox (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    publisher_seq bigint NOT NULL UNIQUE,
    subject text NOT NULL,
    header jsonb NOT NULL,
    payload bytea NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    sent_at timestamptz
);

CREATE INDEX outbox_pending ON {{schema}}.outbox (id) WHERE sent_at IS NULL;

CREATE FUNCTION {{schema}}.reject_change() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION '% rows are immutable', TG_TABLE_NAME;
END
$$;

CREATE FUNCTION {{schema}}.keep_ownership() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_TABLE_NAME = 'definitions' AND (NEW.team_id, NEW.environment_id, NEW.scope, NEW.flow_id) IS DISTINCT FROM (OLD.team_id, OLD.environment_id, OLD.scope, OLD.flow_id) THEN
        RAISE EXCEPTION 'definition ownership and binding are immutable';
    END IF;
    IF TG_TABLE_NAME = 'secrets' AND (NEW.team_id, NEW.secret_id, NEW.environment_id, NEW.key) IS DISTINCT FROM (OLD.team_id, OLD.secret_id, OLD.environment_id, OLD.key) THEN
        RAISE EXCEPTION 'secret ownership and key are immutable';
    END IF;
    RETURN NEW;
END
$$;

CREATE TRIGGER secret_versions_immutable BEFORE UPDATE OR DELETE ON {{schema}}.secret_versions FOR EACH ROW EXECUTE FUNCTION {{schema}}.reject_change();

CREATE TRIGGER revisions_immutable BEFORE UPDATE OR DELETE ON {{schema}}.revisions FOR EACH ROW EXECUTE FUNCTION {{schema}}.reject_change();

CREATE TRIGGER definitions_ownership BEFORE UPDATE ON {{schema}}.definitions FOR EACH ROW EXECUTE FUNCTION {{schema}}.keep_ownership();

CREATE TRIGGER secrets_ownership BEFORE UPDATE ON {{schema}}.secrets FOR EACH ROW EXECUTE FUNCTION {{schema}}.keep_ownership();
