# env-registry

env-registry owns team and Flow launch parameters: ordinary values, logical
secrets with immutable AES-256-GCM encrypted versions, the immutable revision
history, and the per-attempt snapshot an Executor opens when it starts a task.
It stores everything in its own PostgreSQL schema (`env_registry_schema` by
default) and talks to other services only through NATS.

## Interfaces

- **Operator operations**, request/reply on `env-registry.ui.<operation>.sub`
  (queue group `env-registry`), reached only through API Gateway: `list`,
  `create`, `get`, `replace`, `delete`, `list-revisions`, `create-secret`,
  `replace-secret`, `revoke-secret`, `list-secret-versions` and
  `task-parameters`. Request and reply schemas are in `schemas/ui.*`.
- **Executor open edge**, the only HTTP route besides the probes:
  `GET /v1/tasks/{task_id}/launch-parameters/open` with
  `Authorization: Bearer <claim token>`. env-registry verifies the Ed25519 claim
  token, asks task-manager (`task-manager.service.claim-current.pub`) whether
  the claim is current, freezes the attempt snapshot on first open, and
  returns `{"values": {...}}`. Errors are `404 claim_not_current`,
  `503 service_unavailable` and `422 configuration_error`.
- **Requests it sends**: flow-registry `flow-owner` for Flow-scoped writes,
  task-manager `claim-current` for opens.
- **Consumed stream**: task-manager's archived event through the durable
  consumer `env-registry-task-archived` (`schemas/consumers.json`); it deletes
  the task's snapshots.
- **Published through the outbox**: one `env-registry.audit.<action>.pub`
  message per operator mutation or authorization/state rejection, and one
  `env-registry.event.launch_parameters_open.pub` message per verified open.
  No message carries a value, secret, ciphertext, key or token.
- **Probes** on `:8080`: `/v1/livez` and `/v1/readyz`. Readiness requires the
  broker connection, the bound durable consumer and the database.

## Running

The image starts `/env-registry --config /etc/flowai/config.yaml`.
`config.example.yaml` lists every key the service reads. The deployment
mounts NATS credentials at `/run/flowai/nats/user.creds` and the stand CA at
`/run/flowai/stand-ca/ca.pem`, and creates the schema and the durable consumer.

## Tests

```sh
export FLOWAI_ENV_REGISTRY_SCHEMA_DIR=/absolute/path/to/publisher-fixtures
go test -mod=readonly -count=1 ./...
go test -mod=readonly -count=1 -tags=integration ./test
```

Unit tests use the in-memory store and fake broker in `internal/mocks`.
Integration tests (`//go:build integration`) start PostgreSQL in a container.

The fixture directory contains the fixed `flow-registry/schemas/` and
`task-manager/schemas/` paths listed in the qualification workflow. Stage
the files from exact publisher commits and verify their SHA-256 hashes
before running either suite. The workflow stages these files in a temporary
directory outside the checkout. The audited Gitea ownership and schema
declarations are in `qualification/gitea-declarations.json`.
