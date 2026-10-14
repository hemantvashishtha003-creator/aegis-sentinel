const test = require('node:test');
const assert = require('node:assert');
const AuditService = require('../services/auditService');

test('AuditService: Appends events with cryptographic hash chaining and verifies integrity', () => {
  // Append multiple audit events
  AuditService.logEvent({
    eventType: 'TEST_EVENT_ALPHA',
    actorId: 'usr-inv-02',
    actorRole: 'INVESTIGATOR',
    targetEntityType: 'DEVICE',
    targetEntityId: 'dev-lab-01',
    action: 'TEST_ACTION_A',
    details: { note: 'Chain verification step 1' }
  });

  AuditService.logEvent({
    eventType: 'TEST_EVENT_BETA',
    actorId: 'usr-cmd-01',
    actorRole: 'COMMANDER',
    targetEntityType: 'VAULT',
    targetEntityId: 'vault-01',
    action: 'TEST_ACTION_B',
    details: { note: 'Chain verification step 2' }
  });

  const verification = AuditService.verifyChainIntegrity();
  assert.strictEqual(verification.valid, true, 'Cryptographic chain integrity must be valid');
  assert.ok(verification.count >= 3, 'Chain must contain genesis plus appended events');
  assert.ok(verification.latestHash, 'Latest hash must be present');
});
