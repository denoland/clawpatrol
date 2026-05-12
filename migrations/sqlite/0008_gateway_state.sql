-- 0008_gateway_state — collapse on-disk gateway state into sqlite.
--
-- Before this migration the gateway scattered state across the
-- filesystem alongside its sqlite db:
--
--   ${ca_dir}/ca.crt + ca.key              → ca_material
--   ${state_dir}/wg-server.key             → wg_server_key
--   ${ca_dir}/ssh/<endpoint>.key           → gateway_blobs (kind='ssh_host_key')
--   ${CLAWPATROL_DIR}/codex_jwt_keys.json  → gateway_blobs (kind='codex_jwt_keys')
--   ${state_dir}/instance_id               → telemetry_state
--   ${state_dir}/dnsvip.json               → dnsvip_allocations
--
-- After this migration the gateway writes exactly one persistent
-- artifact to disk (the sqlite db). Legacy on-disk files are
-- auto-imported on first boot, then deleted (see state_import.go).
--
-- Tables come in two shapes. Host-owned singletons (CA, WG server
-- key, telemetry id) get typed columns: their shape is fixed and the
-- gateway code is the only consumer, so a typed table is honest
-- about the data and `sqlite3` introspection stays readable.
-- Plugin-owned state goes through gateway_blobs because plugins
-- address it by (kind, name) through runtime.BlobStore and a new
-- plugin shouldn't need a schema migration to land.

CREATE TABLE ca_material (
  id          INTEGER PRIMARY KEY CHECK (id = 1),
  cert_pem    BLOB NOT NULL,
  key_pem     BLOB NOT NULL,
  created_ns  INTEGER NOT NULL
);

CREATE TABLE wg_server_key (
  id          INTEGER PRIMARY KEY CHECK (id = 1),
  priv_hex    TEXT NOT NULL,
  created_ns  INTEGER NOT NULL
);

CREATE TABLE telemetry_state (
  id          INTEGER PRIMARY KEY CHECK (id = 1),
  instance_id TEXT NOT NULL,
  created_ns  INTEGER NOT NULL
);

-- Generic plugin-owned blob store. Plugins address rows by
-- (kind, name); kind is the plugin's stable namespace, name is the
-- sub-key (the SSH endpoint name for ssh_host_key, or empty for
-- plugin-singleton blobs like codex_jwt_keys). New plugins that
-- need persistent bytes use this table — DO NOT dump host-owned
-- typed state here.
CREATE TABLE gateway_blobs (
  kind        TEXT NOT NULL,
  name        TEXT NOT NULL,
  value       BLOB NOT NULL,
  updated_ns  INTEGER NOT NULL,
  PRIMARY KEY (kind, name)
);

-- DNS-VIP allocations. One row per (hostname, v4, v6) triple.
-- RebuildFromPolicy rewrites the whole table inside a single tx so
-- crash-recovery matches the rename-an-atomic-file semantics the
-- old dnsvip.json had.
CREATE TABLE dnsvip_allocations (
  id        INTEGER PRIMARY KEY,
  hostname  TEXT NOT NULL UNIQUE,
  v4        TEXT NOT NULL UNIQUE,
  v6        TEXT NOT NULL UNIQUE
);

INSERT INTO _schema (version) VALUES (8);
