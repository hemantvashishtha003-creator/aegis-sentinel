-- Schema for Advanced Device Security and Incident Response Module (AEGIS-Sentinel)

CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  username TEXT NOT NULL UNIQUE,
  full_name TEXT NOT NULL,
  role TEXT NOT NULL CHECK(role IN ('COMMANDER', 'INVESTIGATOR', 'ANALYST', 'AUDITOR')),
  email TEXT NOT NULL,
  api_key TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS devices (
  id TEXT PRIMARY KEY,
  device_name TEXT NOT NULL,
  serial_number TEXT NOT NULL UNIQUE,
  udid TEXT NOT NULL UNIQUE,
  platform TEXT NOT NULL CHECK(platform IN ('macos', 'windows', 'ios', 'android', 'linux')),
  os_version TEXT NOT NULL,
  enrollment_status TEXT NOT NULL CHECK(enrollment_status IN ('ENROLLED', 'QUARANTINED', 'LOCKED', 'WIPED', 'UNENROLLED')),
  is_lab_device INTEGER NOT NULL DEFAULT 0,
  assigned_user TEXT NOT NULL,
  hardware_model TEXT NOT NULL,
  ip_address TEXT NOT NULL,
  mac_address TEXT NOT NULL,
  enrollment_token TEXT NOT NULL,
  cert_fingerprint TEXT NOT NULL,
  last_seen TEXT NOT NULL,
  enrolled_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS assessments (
  id TEXT PRIMARY KEY,
  target_url TEXT NOT NULL,
  domain TEXT NOT NULL,
  investigator_id TEXT NOT NULL,
  threat_verdict TEXT NOT NULL CHECK(threat_verdict IN ('BENIGN', 'SUSPICIOUS', 'MALICIOUS_PHISHING')),
  risk_score INTEGER NOT NULL,
  lawful_data TEXT NOT NULL,       -- JSON containing DNS, TLS/SSL, HTTP headers, CSP, CORS, WHOIS
  boundary_analysis TEXT NOT NULL, -- JSON containing SOP, browser sandbox, permissions, OS & MDM isolation
  reasons TEXT NOT NULL,           -- JSON array of findings
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS evidence_vault (
  id TEXT PRIMARY KEY,
  incident_id TEXT NOT NULL,
  device_id TEXT NOT NULL,
  evidence_type TEXT NOT NULL CHECK(evidence_type IN ('BROWSER_LOG', 'AUTH_FAILURES', 'DNS_CACHE', 'MEMORY_DUMP_SAMPLE', 'SUSPICIOUS_ARTIFACT', 'SANDBOX_REPORT')),
  title TEXT NOT NULL,
  encrypted_data TEXT NOT NULL,    -- AES-256-GCM ciphertext (Base64)
  iv TEXT NOT NULL,                -- AES-256-GCM IV (Base64)
  auth_tag TEXT NOT NULL,          -- AES-256-GCM Auth Tag (Base64)
  sha256_checksum TEXT NOT NULL,   -- Cryptographic checksum before encryption
  file_size_bytes INTEGER NOT NULL,
  collected_by TEXT NOT NULL,
  collected_at TEXT NOT NULL,
  retention_days INTEGER NOT NULL DEFAULT 90,
  legal_hold INTEGER NOT NULL DEFAULT 0,
  expires_at TEXT NOT NULL,
  metadata TEXT NOT NULL           -- JSON metadata (headers, IOCs, investigator notes)
);

CREATE TABLE IF NOT EXISTS mdm_commands (
  id TEXT PRIMARY KEY,
  device_id TEXT NOT NULL,
  command_type TEXT NOT NULL CHECK(command_type IN ('REMOTE_LOCK', 'QUARANTINE', 'SELECTIVE_WIPE', 'FACTORY_RESET')),
  is_destructive INTEGER NOT NULL DEFAULT 0,
  operator_id TEXT NOT NULL,
  operator_role TEXT NOT NULL,
  confirmation_code TEXT,
  dual_approver_id TEXT,
  reason TEXT NOT NULL,
  status TEXT NOT NULL CHECK(status IN ('PENDING_CONFIRMATION', 'EXECUTED', 'ACKNOWLEDGED', 'FAILED', 'REJECTED')),
  command_payload TEXT NOT NULL,   -- JSON payload (PIN, wipe flags, isolation profiles)
  execution_result TEXT NOT NULL,  -- JSON MDM acknowledgment or error
  signature_hash TEXT NOT NULL,    -- HMAC-SHA256 signature of command details
  created_at TEXT NOT NULL,
  completed_at TEXT
);

CREATE TABLE IF NOT EXISTS lab_scenarios (
  id TEXT PRIMARY KEY,
  scenario_name TEXT NOT NULL,
  category TEXT NOT NULL,
  description TEXT NOT NULL,
  synthetic_user TEXT NOT NULL,              -- JSON mock user credentials and profiles
  attack_vector TEXT NOT NULL,
  browser_protections_tested TEXT NOT NULL,  -- JSON SOP, autofill isolation, CSP, download sandbox
  permission_boundaries_tested TEXT NOT NULL,-- JSON file system, camera, mic, push, clipboard
  synthetic_artifacts TEXT NOT NULL,         -- JSON mock logs and network pcaps
  last_run_at TEXT,
  last_result TEXT                           -- JSON outcome of simulation
);

CREATE TABLE IF NOT EXISTS audit_logs (
  id TEXT PRIMARY KEY,
  event_type TEXT NOT NULL,
  actor_id TEXT NOT NULL,
  actor_role TEXT NOT NULL,
  target_entity_type TEXT NOT NULL,
  target_entity_id TEXT NOT NULL,
  action TEXT NOT NULL,
  details TEXT NOT NULL,           -- JSON extra context
  ip_address TEXT NOT NULL,
  tamper_hash TEXT NOT NULL,       -- SHA-256 blockchain-style chaining
  created_at TEXT NOT NULL
);
