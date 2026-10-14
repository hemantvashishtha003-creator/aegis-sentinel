# 🛡️ AEGIS-SENTINEL: Advanced Device Security & Incident Response Platform

An enterprise-grade device security and incident response system built for investigating phishing attacks, evaluating security boundaries, acquiring encrypted forensic evidence, executing dual-authorized MDM remote responses, and running controlled cyber-range laboratory tests.

---

## 🌟 Key Architecture & Capabilities

```
+-----------------------------------------------------------------------------------------+
|                                    AEGIS-SENTINEL                                       |
|                    Advanced Device Security & Incident Response Engine                  |
+-----------------------------------------------------------------------------------------+
       |                               |                              |
       v                               v                              v
[1. Device Access Assessment]   [2. Forensic Evidence Vault]   [3. MDM Fleet & Response]
  - Lawful URL Intelligence       - AES-256-GCM Encryption       - Network Quarantine
  - DNS & TLS Inspection          - SHA-256 Integrity Check      - Remote Device Lock
  - Browser Sandbox Matrix        - Role-Based Access (RBAC)     - Dual-Auth Factory Reset
  - SOP / Web Permissions Gate    - Legal Hold & Retention       - HMAC-SHA256 Signatures
       |                               |                              |
       +-------------------------------+------------------------------+
                                       |
                                       v
                     [4. Isolated Cyber Range Testing Lab]
                       - Dedicated Synthetic Endpoints
                       - Synthetic Attack Simulations (OAuth, Phish, Form)
                       - Zero Impact on Live Production Hardware
                                       |
                                       v
                     [5. Tamper-Evident Chained Audit Trail]
                       - Blockchain-style SHA-256 Hash Chaining
                       - Real-Time Cryptographic Verification
```

---

## 🔬 1. Device Access Assessment

### Lawful Information Collection from Reported URLs
The module gathers lawful intelligence from a reported URL without unauthorized interaction:
- **DNS Records**: A, AAAA, MX, and TXT/SPF records.
- **TLS/SSL Certificate Telemetry**: Protocol version, Cipher suite, Certificate Authority (CA), validity window, and Subject Alternative Names (SANs).
- **HTTP Security Posture**: Content-Security-Policy (CSP), Strict-Transport-Security (HSTS), X-Frame-Options, X-Content-Type-Options, Referrer-Policy, and Permissions-Policy.
- **Phishing Heuristics**: Raw IP hostname detection, typosquatting indicators, credential harvesting token signatures, and high-risk TLD analysis.

### Security Boundary Analysis
The assessment engine evaluates and articulates why **merely visiting a link cannot compromise host private files or grant MDM system controls**:
1. **Browser Sandbox Boundaries**:
   - **Same-Origin Policy (SOP)**: Isolates DOM, local storage, and cookies. A malicious link has zero access to corporate portal cookies or session tokens.
   - **Cookie Isolation**: `HttpOnly` blocks JavaScript reading; `SameSite=Strict/Lax` prevents cross-site request forgery (CSRF).
   - **Web Permissions API**: Access to microphone, camera, geolocation, Bluetooth, and USB strictly mandates explicit user gesture and browser confirmation dialogs.
   - **File System Access API**: `window.showOpenFilePicker` requires explicit user activation and native file dialog interaction. Web scripts cannot silently traverse disk directories (`C:\`, `/Users/`).
2. **Operating System Sandboxing**:
   - Chromium and modern browser engines operate unprivileged renderer worker processes (Windows AppContainer, Linux seccomp-bpf, macOS Seatbelt).
   - Local credential stores (Windows DPAPI, macOS Keychain, Android Keystore) are completely isolated from browser DOM contexts.
3. **Device Management (MDM) Requirements**:
   - MDM commands (wipe, lock, configuration) can only be dispatched via cryptographically signed push channels (Apple APNs, Windows WNS, Google FCM) linked to an enrolled hardware UDID and enterprise PKI certificate. Web links have zero capability to execute MDM agent commands.

---

## 🔐 2. Authorized Data Collection & Forensic Vault

- **Supported Evidence Types**:
  - `BROWSER_LOG`: Browser navigation history, referrer paths, and SafeBrowsing alerts.
  - `AUTH_FAILURES`: Windows Security Event 4625 / Linux PAM authentication failure telemetry.
  - `DNS_CACHE`: Active client-side DNS resolver cache and queried hostnames.
  - `SUSPICIOUS_ARTIFACT`: Process tree snapshots, active TCP sockets, and MITRE ATT&CK technique mappings.
- **Cryptographic Encryption**:
  - Encrypted using **AES-256-GCM** with a random 96-bit initialization vector (`IV`) and 128-bit authentication tag (`authTag`).
  - Pre-encryption **SHA-256 checksum** is calculated and stored to verify forensic non-tampering (Chain of Custody).
- **Role-Based Access Control (RBAC)**:
  - `COMMANDER` / `INVESTIGATOR`: Can acquire evidence, decrypt ciphertext, inspect raw forensic artifacts, and manage retention.
  - `ANALYST` / `AUDITOR`: Can inspect metadata, hashes, and chain of custody, but cannot view raw decrypted payloads.
- **Retention & Legal Hold**:
  - Configurable retention periods (default: 90 days).
  - `Legal Hold` toggle protects critical evidence from automated retention purging.

---

## 📱 3. Remote Device Reset & MDM Response

- **Enrollment Verification**:
  - Enrolled endpoints receive an MDM Enrollment Token (`MDM-TOK-...`), unique hardware UDID, and SHA-256 Certificate Fingerprint.
  - Commands sent to unenrolled or already wiped devices are rejected with cryptographic verification errors.
- **Incident Response Actions**:
  - **Network Quarantine**: Reconfigures device networking via MDM, isolating traffic strictly to an Incident Remediation VPN.
  - **Remote Lock**: Dispatches screen-lock instruction, sets emergency PIN, and displays incident response guidance.
  - **Dual-Authorization Destructive Factory Reset**:
    - **Phase 1 (Initiate)**: Commander provides operational justification and generates a one-time code (`RESET-<SERIAL>-<TOKEN>`).
    - **Phase 2 (Dual Approval & Execution)**: Live corporate endpoints mandate a distinct secondary approver (`dualApproverId != operatorId`).
    - Every executed command generates an **HMAC-SHA256 signature** recording operator, device identifier, timestamp, and MDM acknowledgment.
    - Prominently distinguishes simulated lab results from verified corporate endpoint wipes.

---

## 🧪 4. Isolated Security Testing Lab

- **Controlled Cyber Range**:
  - Pre-provisioned test devices (`LAB-MAC-M3-SANDBOX-01`, `LAB-WIN11-EDGE-GUARD-02`, etc.) and synthetic user identities (`alice.investor@synthetic-corp.test`).
  - Strict safety restriction: Lab simulations **cannot** be executed against live corporate endpoints.
- **Pre-Built Attack Scenarios**:
  - **Scenario 1**: Credential Harvesting & Autofill Domain Gate Test.
  - **Scenario 2**: Fake MDM Profile & Malicious `.mobileconfig` Vector.
  - **Scenario 3**: Malicious Script Web API & Device Permission Probing.
- **Clear Distinction**:
  - All test results are watermarked: `[CONTROLLED_LABORATORY_SYNTHETIC_DATA]`.
  - Guarantees zero interaction with third-party networks or unauthorized devices.

---

## 📜 5. Tamper-Evident Audit Trail

- Every action (URL assessment, evidence ingestion, quarantine, lock, factory reset, legal hold) is appended to an immutable audit ledger.
- Each block contains a **SHA-256 tamper hash** linking to the previous block's hash:
  $$\text{TamperHash}_n = \text{SHA256}(\text{TamperHash}_{n-1} \parallel \text{ID} \parallel \text{Event} \parallel \text{Actor} \parallel \text{Action} \parallel \text{Target} \parallel \text{Payload} \parallel \text{Time})$$
- Real-time **Chain Integrity Verification** validates the entire cryptographic ledger on demand.

---

## 🚀 Quickstart & Deployment

### 1. Prerequisites
- Node.js v20+ (Node v24.19 recommended; utilizes built-in `node:sqlite` and `node:crypto`).

### 2. Installation
```bash
git clone <repo-url>
cd "Security Gardddd"
npm install
```

### 3. Run Automated Security Tests
```bash
npm test
```
The test suite validates:
- Lawful URL assessment and threat scoring.
- Browser sandbox and permission boundary enforcement.
- AES-256-GCM encryption, decryption, and SHA-256 checksums.
- RBAC access restrictions on evidence.
- Legal hold retention protection.
- MDM enrollment, quarantine, and remote lock.
- Dual-authorization enforcement on live factory reset.
- Safety barriers preventing lab tests on live devices.
- Cryptographic audit chain integrity verification.

### 4. Start the Application Server (Local Node.js)
```bash
npm start
```
Open [http://127.0.0.1:3000](http://127.0.0.1:3000) in your web browser.

---

## 🐳 Production Deployment with Docker & Docker Compose

The platform includes a containerized production setup with **Nginx reverse proxy**, rate limiting, non-root security, persistent storage, and automated health checks.

### Option A: One-Command Deployment (Linux / Cloud VPS)
```bash
chmod +x deploy.sh
./deploy.sh
```

### Option B: Windows Deployment (PowerShell)
```powershell
.\deploy.ps1
```

### Option C: Manual Docker Compose
```bash
# 1. Create environment file from template
cp .env.example .env

# 2. Build and launch services in background
docker compose up -d --build

# 3. Check container health
docker compose ps
```
The application will be accessible via:
* **Production Gateway (Nginx Reverse Proxy):** `http://<server-ip>:80` or `http://localhost`
* **Direct Application Port:** `http://<server-ip>:3000`

---

## 👥 Built-in Personas for Testing (RBAC)

Use the top-right **Operator Persona Selector** in the UI to test role-based permissions:
| Persona | Name | Role | Privileges |
| :--- | :--- | :--- | :--- |
| `usr-cmd-01` | Vance Sterling | `COMMANDER` | Full control, initiate/authorize factory reset, toggle legal hold, purge retention. |
| `usr-inv-02` | Elena Chen | `INVESTIGATOR` | Run URL assessments, acquire evidence, decrypt vault items, quarantine/lock endpoints. |
| `usr-ana-03` | Marcus Thorne | `ANALYST` | View telemetry, inspect URL assessments, run lab simulations (evidence decryption restricted). |
| `usr-aud-04` | Sarah Novak | `AUDITOR` | Read-only inspection of tamper-evident audit logs and chain verification. |

---

## 📡 API Endpoints Summary

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/api/stats/dashboard-stats` | High-level SOC telemetry and fleet metrics. |
| `POST` | `/api/assessment/scan` | Lawful URL intelligence & boundary analysis. |
| `GET` | `/api/assessment` | List past URL assessments. |
| `POST` | `/api/evidence/acquire` | Acquire and AES-256-GCM encrypt forensic evidence. |
| `GET` | `/api/evidence` | List evidence vault metadata and checksums. |
| `GET` | `/api/evidence/:id` | Decrypt and inspect evidence artifact (RBAC enforced). |
| `PATCH` | `/api/evidence/:id/legal-hold` | Toggle Legal Hold status. |
| `POST` | `/api/evidence/purge-expired` | Purge expired non-held evidence records. |
| `GET` | `/api/mdm/devices` | List managed endpoints (live and lab). |
| `POST` | `/api/mdm/devices/enroll` | Enroll a new endpoint with certificate fingerprint. |
| `POST` | `/api/mdm/quarantine` | Isolate device to remediation VPN. |
| `POST` | `/api/mdm/lock` | Remote PIN-lock with custom incident message. |
| `POST` | `/api/mdm/factory-reset/initiate` | Phase 1: Generate one-time reset confirmation code. |
| `POST` | `/api/mdm/factory-reset/confirm` | Phase 2: Dual-authorized destructive wipe execution. |
| `GET` | `/api/lab/scenarios` | List cyber-range synthetic scenarios. |
| `POST` | `/api/lab/run` | Execute isolated simulation on lab test device. |
| `GET` | `/api/audit/logs` | List tamper-evident chained audit logs. |
| `GET` | `/api/audit/verify-chain` | Cryptographically verify SHA-256 hash chain integrity. |

---

## 🔒 Security & Defensive Guarantees
1. **Zero Silent Hardware Access**: Merely visiting a link never grants access to private host storage, camera, microphone, or system commands.
2. **Dual-Authorization on Destructive Commands**: Full factory resets on live devices cannot be executed by a single user or without verified enrollment.
3. **Cryptographic Proof of Action**: Every command generates an HMAC-SHA256 signature and immutable audit log entry.
4. **Isolated Cyber Range**: Simulated testing strictly targets designated lab endpoints and synthetic user identities.
