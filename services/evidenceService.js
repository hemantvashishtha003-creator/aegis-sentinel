const crypto = require('crypto');
const db = require('../db');
const config = require('../config');
const AuditService = require('./auditService');

class EvidenceService {
  /**
   * Derives a 32-byte cryptographic key for AES-256-GCM
   */
  static getEncryptionKey() {
    return crypto.createHash('sha256').update(config.MASTER_ENCRYPTION_KEY).digest();
  }

  /**
   * Encrypts plaintext data using AES-256-GCM and generates a SHA-256 pre-encryption checksum
   */
  static encryptPayload(plainTextData) {
    const key = this.getEncryptionKey();
    const iv = crypto.randomBytes(12); // Standard 96-bit IV for GCM
    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);

    const inputBuffer = Buffer.isBuffer(plainTextData) ? plainTextData : Buffer.from(plainTextData, 'utf8');
    
    // Cryptographic pre-encryption checksum for chain of custody
    const sha256Checksum = crypto.createHash('sha256').update(inputBuffer).digest('hex');

    const encrypted = Buffer.concat([cipher.update(inputBuffer), cipher.final()]);
    const authTag = cipher.getAuthTag();

    return {
      cipherTextBase64: encrypted.toString('base64'),
      ivBase64: iv.toString('base64'),
      authTagBase64: authTag.toString('base64'),
      sha256Checksum,
      fileSizeBytes: inputBuffer.length
    };
  }

  /**
   * Decrypts AES-256-GCM ciphertext and validates integrity and auth tag
   */
  static decryptPayload(cipherTextBase64, ivBase64, authTagBase64, expectedChecksum) {
    const key = this.getEncryptionKey();
    const iv = Buffer.from(ivBase64, 'base64');
    const authTag = Buffer.from(authTagBase64, 'base64');
    const cipherText = Buffer.from(cipherTextBase64, 'base64');

    const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
    decipher.setAuthTag(authTag);

    const decrypted = Buffer.concat([decipher.update(cipherText), decipher.final()]);

    // Verify chain of custody checksum
    const calculatedChecksum = crypto.createHash('sha256').update(decrypted).digest('hex');
    const checksumValid = calculatedChecksum === expectedChecksum;

    return {
      decryptedText: decrypted.toString('utf8'),
      checksumValid,
      calculatedChecksum
    };
  }

  /**
   * Acquires forensic evidence from an authorized device
   */
  static async acquireDeviceEvidence({
    deviceId,
    incidentId = 'INC-2026-PHISH-01',
    evidenceType = 'BROWSER_LOG',
    actorId = 'usr-inv-02',
    actorRole = 'INVESTIGATOR',
    customNotes = '',
    retentionDays = config.DEFAULT_RETENTION_DAYS
  }) {
    // 1. RBAC Verification
    if (!['COMMANDER', 'INVESTIGATOR'].includes(actorRole)) {
      throw new Error(`Unauthorized role '${actorRole}': Only COMMANDER or INVESTIGATOR can acquire forensic evidence.`);
    }

    // 2. Device Enrollment & Authorization Check
    const device = db.prepare('SELECT * FROM devices WHERE id = ?').get(deviceId);
    if (!device) {
      throw new Error(`Device ID '${deviceId}' does not exist.`);
    }

    if (device.enrollment_status === 'UNENROLLED') {
      throw new Error(`Device '${device.device_name}' (${device.serial_number}) is UNENROLLED. Evidence acquisition is restricted to verified enrolled endpoints.`);
    }

    // 3. Generate Forensic Artifact Data (Simulated telemetry based on OS and evidence type)
    const rawArtifact = this.generateForensicArtifact({ device, evidenceType, customNotes });
    const rawString = JSON.stringify(rawArtifact, null, 2);

    // 4. Encrypt with AES-256-GCM
    const { cipherTextBase64, ivBase64, authTagBase64, sha256Checksum, fileSizeBytes } = this.encryptPayload(rawString);

    const evidenceId = `evd-${Date.now()}-${crypto.randomBytes(4).toString('hex')}`;
    const now = new Date();
    const collectedAt = now.toISOString();

    const expiresDate = new Date(now.getTime() + retentionDays * 24 * 60 * 60 * 1000);
    const expiresAt = expiresDate.toISOString();

    const title = `${evidenceType} - ${device.device_name} (${device.serial_number})`;

    const metadata = {
      deviceId: device.id,
      deviceName: device.device_name,
      platform: device.platform,
      osVersion: device.os_version,
      serialNumber: device.serial_number,
      isLabDevice: Boolean(device.is_lab_device),
      investigatorNotes: customNotes,
      mitreAttack: rawArtifact.mitreAttack || ['T1566.002 - Phishing: Spearphishing Link']
    };

    const stmt = db.prepare(`
      INSERT INTO evidence_vault (
        id, incident_id, device_id, evidence_type, title, encrypted_data,
        iv, auth_tag, sha256_checksum, file_size_bytes, collected_by,
        collected_at, retention_days, legal_hold, expires_at, metadata
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);

    stmt.run(
      evidenceId,
      incidentId,
      deviceId,
      evidenceType,
      title,
      cipherTextBase64,
      ivBase64,
      authTagBase64,
      sha256Checksum,
      fileSizeBytes,
      actorId,
      collectedAt,
      retentionDays,
      0, // legal_hold default 0
      expiresAt,
      JSON.stringify(metadata)
    );

    // 5. Append Audit Event
    AuditService.logEvent({
      eventType: 'EVIDENCE_ACQUIRED_AND_ENCRYPTED',
      actorId,
      actorRole,
      targetEntityType: 'EVIDENCE_RECORD',
      targetEntityId: evidenceId,
      action: 'ACQUIRE_DEVICE_EVIDENCE',
      details: {
        evidenceId,
        incidentId,
        deviceId,
        evidenceType,
        sha256Checksum,
        fileSizeBytes,
        retentionDays,
        isLabDevice: device.is_lab_device
      }
    });

    return {
      evidenceId,
      title,
      incidentId,
      deviceId,
      evidenceType,
      sha256Checksum,
      fileSizeBytes,
      collectedAt,
      expiresAt,
      legalHold: false,
      cipherSuite: 'AES-256-GCM-SHA256'
    };
  }

  /**
   * Generates realistic forensic indicators based on device platform & evidence type
   */
  static generateForensicArtifact({ device, evidenceType, customNotes }) {
    const timestamp = new Date().toISOString();

    switch (evidenceType) {
      case 'BROWSER_LOG':
        return {
          artifactType: 'FORENSIC_BROWSER_HISTORY_AND_REQUESTS',
          collectionTimestamp: timestamp,
          targetHost: device.device_name,
          platform: device.platform,
          browser: device.platform === 'macos' ? 'Google Chrome 130.0 / Safari 18.0' : 'Microsoft Edge 130.0',
          simulatedNavigationEvents: [
            {
              time: new Date(Date.now() - 3600000).toISOString(),
              url: 'https://mail.corp-acme.internal/inbox',
              method: 'GET',
              statusCode: 200,
              referrer: 'DIRECT'
            },
            {
              time: new Date(Date.now() - 1800000).toISOString(),
              url: 'https://auth-verification-portal.dev/login?ref=urgency_ticket_892',
              method: 'GET',
              statusCode: 200,
              referrer: 'https://mail.corp-acme.internal/inbox',
              browserFlags: {
                safeBrowsingWarningTriggered: true,
                autofillPrevented: true,
                originMismatch: true
              }
            }
          ],
          cachedDnsQueries: [
            { query: 'auth-verification-portal.dev', resolvedIp: '198.51.100.42', ttl: 300 }
          ],
          mitreAttack: ['T1566.002 - Spearphishing Link', 'T1204.001 - User Execution: Malicious Link'],
          notes: customNotes
        };

      case 'AUTH_FAILURES':
        return {
          artifactType: 'SECURITY_AUTH_TELEMETRY',
          collectionTimestamp: timestamp,
          targetHost: device.device_name,
          logChannel: device.platform === 'windows' ? 'Security.evtx (EventID 4625)' : '/var/log/auth.log',
          events: [
            {
              eventCode: device.platform === 'windows' ? 4625 : 'PAM_AUTH_FAIL',
              subStatus: '0xC000006D',
              accountName: device.assigned_user,
              workstation: device.device_name,
              sourceIp: '198.51.100.42',
              failureReason: 'Pre-authentication password mismatch or invalid token format',
              time: new Date(Date.now() - 900000).toISOString()
            }
          ],
          mitreAttack: ['T1110 - Brute Force', 'T1078 - Valid Accounts'],
          notes: customNotes
        };

      case 'DNS_CACHE':
        return {
          artifactType: 'ENDPOINT_DNS_CLIENT_CACHE',
          collectionTimestamp: timestamp,
          targetHost: device.device_name,
          entries: [
            { recordName: 'auth-verification-portal.dev', recordType: 'A', data: '198.51.100.42', timeToLive: 240 },
            { recordName: 'telemetry-beacon.ru.phish-cdn.xyz', recordType: 'CNAME', data: 'sinkhole.test', timeToLive: 60 }
          ],
          mitreAttack: ['T1071.004 - Application Layer Protocol: DNS'],
          notes: customNotes
        };

      case 'SUSPICIOUS_ARTIFACT':
      default:
        return {
          artifactType: 'TRIAGE_FORENSIC_SNAPSHOT',
          collectionTimestamp: timestamp,
          targetHost: device.device_name,
          activeNetworkSockets: [
            { local: `${device.ip_address}:54210`, remote: '198.51.100.42:443', state: 'ESTABLISHED', process: 'chrome.exe' }
          ],
          runningSecurityDaemons: ['FalconSensor', 'DefenderATP', 'JamfDaemon'],
          mitreAttack: ['T1059 - Command and Scripting Interpreter'],
          notes: customNotes
        };
    }
  }

  /**
   * Retrieves list of evidence records (metadata only for general views)
   */
  static listEvidence({ incidentId, limit = 50, offset = 0 } = {}) {
    let query = 'SELECT id, incident_id, device_id, evidence_type, title, sha256_checksum, file_size_bytes, collected_by, collected_at, retention_days, legal_hold, expires_at, metadata FROM evidence_vault';
    const params = [];

    if (incidentId) {
      query += ' WHERE incident_id = ?';
      params.push(incidentId);
    }

    query += ' ORDER BY rowid DESC LIMIT ? OFFSET ?';
    params.push(limit, offset);

    const rows = db.prepare(query).all(...params);
    return rows.map(r => ({
      ...r,
      metadata: JSON.parse(r.metadata),
      legalHold: Boolean(r.legal_hold),
      isExpired: new Date(r.expires_at) < new Date()
    }));
  }

  /**
   * Decrypts and retrieves raw evidence content with RBAC enforcement
   */
  static getEvidenceDetail({ evidenceId, actorId = 'usr-inv-02', actorRole = 'INVESTIGATOR' }) {
    const row = db.prepare('SELECT * FROM evidence_vault WHERE id = ?').get(evidenceId);
    if (!row) {
      throw new Error(`Evidence item '${evidenceId}' not found.`);
    }

    const metadata = JSON.parse(row.metadata);

    // RBAC check: AUDITOR or ANALYST cannot view decrypted raw payload
    if (!['COMMANDER', 'INVESTIGATOR'].includes(actorRole)) {
      AuditService.logEvent({
        eventType: 'UNAUTHORIZED_EVIDENCE_DECRYPTION_ATTEMPT',
        actorId,
        actorRole,
        targetEntityType: 'EVIDENCE_RECORD',
        targetEntityId: evidenceId,
        action: 'ACCESS_DENIED',
        details: { reason: 'Role does not possess raw evidence decryption privilege' }
      });

      return {
        id: row.id,
        title: row.title,
        incidentId: row.incident_id,
        deviceId: row.device_id,
        evidenceType: row.evidence_type,
        sha256Checksum: row.sha256_checksum,
        fileSizeBytes: row.file_size_bytes,
        collectedBy: row.collected_by,
        collectedAt: row.collected_at,
        expiresAt: row.expires_at,
        legalHold: Boolean(row.legal_hold),
        metadata,
        isEncrypted: true,
        accessRestricted: true,
        message: 'Decryption restricted: Role must be COMMANDER or INVESTIGATOR.'
      };
    }

    // Decrypt AES-256-GCM
    const { decryptedText, checksumValid, calculatedChecksum } = this.decryptPayload(
      row.encrypted_data,
      row.iv,
      row.auth_tag,
      row.sha256_checksum
    );

    // Audit log evidence access
    AuditService.logEvent({
      eventType: 'EVIDENCE_DECRYPTED_AND_ACCESSED',
      actorId,
      actorRole,
      targetEntityType: 'EVIDENCE_RECORD',
      targetEntityId: evidenceId,
      action: 'DECRYPT_EVIDENCE',
      details: {
        evidenceId,
        checksumVerified: checksumValid,
        calculatedChecksum
      }
    });

    let parsedContent;
    try {
      parsedContent = JSON.parse(decryptedText);
    } catch {
      parsedContent = decryptedText;
    }

    return {
      id: row.id,
      title: row.title,
      incidentId: row.incident_id,
      deviceId: row.device_id,
      evidenceType: row.evidence_type,
      sha256Checksum: row.sha256_checksum,
      checksumValid,
      fileSizeBytes: row.file_size_bytes,
      collectedBy: row.collected_by,
      collectedAt: row.collected_at,
      expiresAt: row.expires_at,
      legalHold: Boolean(row.legal_hold),
      metadata,
      decryptedContent: parsedContent,
      cipherSuite: 'AES-256-GCM'
    };
  }

  /**
   * Updates the legal hold status of an evidence item
   */
  static setLegalHold({ evidenceId, legalHold, actorId = 'usr-cmd-01', actorRole = 'COMMANDER' }) {
    if (actorRole !== 'COMMANDER') {
      throw new Error('Only an Incident COMMANDER can modify Legal Hold status.');
    }

    const row = db.prepare('SELECT id, legal_hold FROM evidence_vault WHERE id = ?').get(evidenceId);
    if (!row) {
      throw new Error(`Evidence '${evidenceId}' not found.`);
    }

    const holdVal = legalHold ? 1 : 0;
    db.prepare('UPDATE evidence_vault SET legal_hold = ? WHERE id = ?').run(holdVal, evidenceId);

    AuditService.logEvent({
      eventType: 'EVIDENCE_LEGAL_HOLD_MODIFIED',
      actorId,
      actorRole,
      targetEntityType: 'EVIDENCE_RECORD',
      targetEntityId: evidenceId,
      action: holdVal ? 'ENABLE_LEGAL_HOLD' : 'DISABLE_LEGAL_HOLD',
      details: { evidenceId, legalHold: Boolean(holdVal) }
    });

    return { evidenceId, legalHold: Boolean(holdVal) };
  }

  /**
   * Purges expired evidence respecting Legal Hold
   */
  static purgeExpiredEvidence({ actorId = 'usr-cmd-01', actorRole = 'COMMANDER' }) {
    if (actorRole !== 'COMMANDER') {
      throw new Error('Only COMMANDER role can initiate evidence retention purge.');
    }

    const now = new Date().toISOString();
    const expiredRows = db.prepare(`
      SELECT id, title, sha256_checksum FROM evidence_vault
      WHERE expires_at < ? AND legal_hold = 0
    `).all(now);

    if (expiredRows.length === 0) {
      return { purgedCount: 0, items: [] };
    }

    const deleteStmt = db.prepare('DELETE FROM evidence_vault WHERE id = ?');
    for (const item of expiredRows) {
      deleteStmt.run(item.id);
      AuditService.logEvent({
        eventType: 'EVIDENCE_PURGED_RETENTION_POLICY',
        actorId,
        actorRole,
        targetEntityType: 'EVIDENCE_RECORD',
        targetEntityId: item.id,
        action: 'PURGE_EXPIRED_EVIDENCE',
        details: { evidenceId: item.id, title: item.title, sha256Checksum: item.sha256_checksum }
      });
    }

    return {
      purgedCount: expiredRows.length,
      items: expiredRows.map(r => r.id)
    };
  }
}

module.exports = EvidenceService;
