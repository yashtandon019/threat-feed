CREATE TABLE threats (
  id TEXT PRIMARY KEY,
  kind TEXT NOT NULL,
  tier INTEGER NOT NULL,
  title TEXT NOT NULL,
  severity TEXT NOT NULL,
  details TEXT NOT NULL,
  summary TEXT NOT NULL,
  summary_model TEXT NOT NULL,
  summary_hash TEXT,
  content_hash TEXT NOT NULL,
  epss REAL,
  kev_added TEXT,
  kev_due TEXT,
  ransomware INTEGER NOT NULL DEFAULT 0,
  status TEXT NOT NULL,
  first_seen TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  last_signal_at TEXT NOT NULL
);
CREATE INDEX threats_feed ON threats (status, tier, last_signal_at);

CREATE TABLE aliases (
  alias TEXT PRIMARY KEY,
  threat_id TEXT NOT NULL
);
CREATE INDEX aliases_threat ON aliases (threat_id);

CREATE TABLE affected (
  threat_id TEXT NOT NULL,
  ecosystem TEXT NOT NULL,
  package TEXT NOT NULL,
  ranges_json TEXT NOT NULL,
  versions_json TEXT NOT NULL
);
CREATE INDEX affected_threat ON affected (threat_id);
CREATE INDEX affected_pkg ON affected (ecosystem, package);

CREATE TABLE source_records (
  source TEXT NOT NULL,
  source_id TEXT NOT NULL,
  threat_id TEXT NOT NULL,
  url TEXT NOT NULL,
  content_hash TEXT NOT NULL,
  record_json TEXT NOT NULL,
  fetched_at TEXT NOT NULL,
  PRIMARY KEY (source, source_id)
);
CREATE INDEX source_records_threat ON source_records (threat_id);

CREATE TABLE cursors (
  source TEXT PRIMARY KEY,
  cursor TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
