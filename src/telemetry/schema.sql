-- vibe-sec Telemetry Database Schema
-- Run once via: wrangler d1 execute vibe-sec-telemetry --file=src/telemetry/schema.sql

CREATE TABLE IF NOT EXISTS events (
  id                INTEGER PRIMARY KEY AUTOINCREMENT,
  ts                TEXT    NOT NULL,              -- ISO 8601 timestamp from client
  event             TEXT    NOT NULL,              -- Event name (whitelist-validated)
  device_id         TEXT    NOT NULL,              -- Anonymous UUID, never linked to identity
  version           TEXT,                          -- vibe-sec version
  os_version        TEXT,                          -- macOS version
  node_version      TEXT,                          -- Node.js version

  -- scan_complete fields
  findings_total    INTEGER,
  findings_critical INTEGER,
  findings_high     INTEGER,
  findings_medium   INTEGER,
  finding_types     TEXT,                          -- JSON array of category IDs

  -- block_triggered fields
  block_level       TEXT,                          -- "L1", "L2", "L3"
  block_type        TEXT,                          -- Category: "rm_rf", "exfil", etc.
  tool              TEXT,                          -- "Bash", "Write", "Edit"

  -- setup_complete fields
  daemon_installed  INTEGER,                       -- 0/1 boolean
  gemini_configured INTEGER,                       -- 0/1 boolean
  ai_tools          TEXT,                          -- JSON object: { cursor: true, ... }

  created_at        TEXT    DEFAULT (datetime('now'))
);

-- Indexes for common queries
CREATE INDEX IF NOT EXISTS idx_events_event      ON events(event);
CREATE INDEX IF NOT EXISTS idx_events_ts         ON events(ts);
CREATE INDEX IF NOT EXISTS idx_events_device     ON events(device_id);
CREATE INDEX IF NOT EXISTS idx_events_created    ON events(created_at);
CREATE INDEX IF NOT EXISTS idx_events_block_type ON events(block_type) WHERE event = 'block_triggered';
