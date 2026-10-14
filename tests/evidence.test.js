const test = require('node:test');
const assert = require('node:assert');
const EvidenceService = require('../services/evidenceService');
const db = require('../db');

test('EvidenceService: AES-256-GCM encryption and decryption round-trip with checksum verification', () => {
  const secretData = JSON.stringify({
    credentialArtifact: 'SYNTHETIC_MOCK_TOKEN_9941',
    user: 'test.user@corp.internal',
    compromisedUrl: 'https://phish.test/auth'
  });

  const encrypted = EvidenceService.encryptPayload(secretData);
  assert.ok(encrypted.cipherTextBase64, 'Must produce base64 ciphertext');
  assert.ok(encrypted.ivBase64, 'Must produce base64 IV');
  assert.ok(encrypted.authTagBase64, 'Must produce base64 auth tag');
  assert.ok(encrypted.sha256Checksum, 'Must produce SHA-256 checksum');

  const decrypted = EvidenceService.decryptPayload(
    encrypted.cipherTextBase64,
    encrypted.ivBase64,
    encrypted.authTagBase64,
    encrypted.sha256Checksum
  );

  assert.strictEqual(decrypted.checksumValid, true, 'Integrity checksum must match');
  assert.strictEqual(decrypted.decryptedText, secretData, 'Decrypted text must match original');
});

test('EvidenceService: Acquires evidence from authorized device and enforces RBAC', async () => {
  // Acquire from test device 'dev-lab-01'
  const acquired = await EvidenceService.acquireDeviceEvidence({
    deviceId: 'dev-lab-01',
    incidentId: 'INC-TEST-001',
    evidenceType: 'BROWSER_LOG',
    actorId: 'usr-inv-02',
    actorRole: 'INVESTIGATOR',
    customNotes: 'Automated test acquisition'
  });

  assert.ok(acquired.evidenceId, 'Should return evidence ID');
  assert.strictEqual(acquired.cipherSuite, 'AES-256-GCM-SHA256');

  // RBAC Test: INVESTIGATOR can decrypt
  const investigatorAccess = EvidenceService.getEvidenceDetail({
    evidenceId: acquired.evidenceId,
    actorId: 'usr-inv-02',
    actorRole: 'INVESTIGATOR'
  });
  assert.strictEqual(investigatorAccess.checksumValid, true);
  assert.ok(investigatorAccess.decryptedContent, 'Investigator must receive decrypted payload');

  // RBAC Test: AUDITOR cannot decrypt raw payload
  const auditorAccess = EvidenceService.getEvidenceDetail({
    evidenceId: acquired.evidenceId,
    actorId: 'usr-aud-04',
    actorRole: 'AUDITOR'
  });
  assert.strictEqual(auditorAccess.accessRestricted, true);
  assert.strictEqual(auditorAccess.decryptedContent, undefined, 'Auditor must NOT receive decrypted payload');
});

test('EvidenceService: Legal Hold prevents automated retention purge', () => {
  // Insert synthetic expired evidence
  const pastDate = new Date(Date.now() - 100000000).toISOString();
  const { cipherTextBase64, ivBase64, authTagBase64, sha256Checksum } = EvidenceService.encryptPayload('sample dummy log');
  const testEvidenceId = 'evd-test-purge-01';

  db.prepare(`
    INSERT INTO evidence_vault (
      id, incident_id, device_id, evidence_type, title, encrypted_data,
      iv, auth_tag, sha256_checksum, file_size_bytes, collected_by,
      collected_at, retention_days, legal_hold, expires_at, metadata
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    testEvidenceId, 'INC-TEST', 'dev-lab-01', 'DNS_CACHE', 'Test Retention Log',
    cipherTextBase64, ivBase64, authTagBase64, sha256Checksum, 100,
    'usr-cmd-01', pastDate, 30, 1, pastDate, JSON.stringify({}) // legal_hold = 1
  );

  // Attempt purge
  const purgeResult = EvidenceService.purgeExpiredEvidence({ actorId: 'usr-cmd-01', actorRole: 'COMMANDER' });
  assert.ok(!purgeResult.items.includes(testEvidenceId), 'Item on legal hold must NOT be purged');

  // Remove legal hold
  EvidenceService.setLegalHold({ evidenceId: testEvidenceId, legalHold: false, actorRole: 'COMMANDER' });

  // Second purge should now delete it
  const secondPurge = EvidenceService.purgeExpiredEvidence({ actorId: 'usr-cmd-01', actorRole: 'COMMANDER' });
  assert.ok(secondPurge.items.includes(testEvidenceId), 'Item without legal hold must be purged after expiration');
});
