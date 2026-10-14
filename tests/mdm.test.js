const test = require('node:test');
const assert = require('node:assert');
const MdmService = require('../services/mdmService');
const db = require('../db');

test('MdmService: Device Enrollment, Remote Quarantine, and Remote Lock', async () => {
  const serial = `TEST-SRL-${Date.now().toString().slice(-6)}`;
  const enrolled = MdmService.enrollDevice({
    deviceName: 'TEST-MAC-ENROLLED-99',
    serialNumber: serial,
    platform: 'macos',
    osVersion: 'macOS 15.1',
    assignedUser: 'qa.tester@corp.internal',
    isLabDevice: 1,
    hardwareModel: 'MacBook Air M3'
  });

  assert.ok(enrolled.id, 'Device should have an ID');
  assert.strictEqual(enrolled.enrollment_status, 'ENROLLED');
  assert.ok(enrolled.cert_fingerprint.startsWith('SHA256:'), 'Must issue cryptographic certificate fingerprint');

  // Test Quarantine
  const quarResult = await MdmService.quarantineDevice({
    deviceId: enrolled.id,
    actorId: 'usr-inv-02',
    actorRole: 'INVESTIGATOR',
    reason: 'Quarantine test run'
  });
  assert.strictEqual(quarResult.status, 'QUARANTINED');
  assert.ok(quarResult.signature, 'Quarantine command must carry HMAC signature');

  // Verify DB state
  const deviceAfterQuar = MdmService.getDeviceById(enrolled.id);
  assert.strictEqual(deviceAfterQuar.enrollment_status, 'QUARANTINED');

  // Test Remote Lock
  const lockResult = await MdmService.remoteLock({
    deviceId: enrolled.id,
    lockPin: '882199',
    customMessage: 'Device locked under test procedure',
    actorId: 'usr-inv-02',
    actorRole: 'INVESTIGATOR'
  });
  assert.strictEqual(lockResult.status, 'LOCKED');
  assert.ok(lockResult.signature, 'Remote lock must carry HMAC signature');
});

test('MdmService: Destructive Factory Reset requires explicit confirmation code & dual approval on live devices', async () => {
  // 1. Test against Lab Device (Phase 1 & 2)
  const labDevice = db.prepare("SELECT * FROM devices WHERE is_lab_device = 1 AND enrollment_status != 'WIPED' LIMIT 1").get();
  assert.ok(labDevice, 'Must have at least one active lab device');

  const initResult = MdmService.initiateFactoryReset({
    deviceId: labDevice.id,
    actorId: 'usr-cmd-01',
    actorRole: 'COMMANDER',
    reason: 'Phishing attack triage complete; resetting test lab device.'
  });

  assert.strictEqual(initResult.status, 'PENDING_CONFIRMATION');
  assert.ok(initResult.confirmationCode, 'Must generate confirmation code');

  // Wrong confirmation code must fail
  assert.throws(() => {
    MdmService.confirmFactoryReset({
      commandId: initResult.commandId,
      confirmationCode: 'INVALID-CODE-999',
      actorId: 'usr-cmd-01',
      actorRole: 'COMMANDER'
    });
  }, /Confirmation code mismatch/, 'Invalid code must be rejected');

  // Valid confirmation code executes factory reset
  const confirmResult = MdmService.confirmFactoryReset({
    commandId: initResult.commandId,
    confirmationCode: initResult.confirmationCode,
    actorId: 'usr-cmd-01',
    actorRole: 'COMMANDER'
  });

  assert.strictEqual(confirmResult.status, 'WIPED');
  assert.strictEqual(confirmResult.executionResult.isSimulated, true);
  assert.match(confirmResult.executionResult.simulationDisclaimer, /SIMULATED LAB RESULT/);

  // 2. Dual Authorization enforcement on LIVE corporate device
  const liveDevice = db.prepare("SELECT * FROM devices WHERE is_lab_device = 0 AND enrollment_status != 'WIPED' LIMIT 1").get();
  assert.ok(liveDevice, 'Must have active live device');

  const liveInit = MdmService.initiateFactoryReset({
    deviceId: liveDevice.id,
    actorId: 'usr-cmd-01',
    actorRole: 'COMMANDER',
    reason: 'Executive device compromised via zero-day link, critical wipe required.'
  });

  // Must reject if same operator tries to be dual approver
  assert.throws(() => {
    MdmService.confirmFactoryReset({
      commandId: liveInit.commandId,
      confirmationCode: liveInit.confirmationCode,
      dualApproverId: 'usr-cmd-01', // Same as operator
      actorId: 'usr-cmd-01',
      actorRole: 'COMMANDER'
    });
  }, /Dual authorization violation/, 'Dual approval cannot be self-approved on live device');

  // Dual approval with distinct investigator succeeds
  const liveConfirm = MdmService.confirmFactoryReset({
    commandId: liveInit.commandId,
    confirmationCode: liveInit.confirmationCode,
    dualApproverId: 'usr-inv-02', // Elena Chen (verified investigator)
    actorId: 'usr-cmd-01',
    actorRole: 'COMMANDER'
  });

  assert.strictEqual(liveConfirm.status, 'WIPED');
  assert.strictEqual(liveConfirm.executionResult.isSimulated, false);
  assert.match(liveConfirm.executionResult.simulationDisclaimer, /LIVE DESTRUCTIVE ACTION/);
});
