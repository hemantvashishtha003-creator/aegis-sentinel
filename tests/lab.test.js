const test = require('node:test');
const assert = require('node:assert');
const LabService = require('../services/labService');
const db = require('../db');

test('LabService: Runs isolated laboratory scenario on synthetic device', async () => {
  const scenarios = LabService.listScenarios();
  assert.ok(scenarios.length >= 3, 'Must list available lab scenarios');

  const labDevice = db.prepare('SELECT id FROM devices WHERE is_lab_device = 1 LIMIT 1').get();
  assert.ok(labDevice, 'Must have a lab device');

  const simResult = await LabService.runScenario({
    scenarioId: scenarios[0].id,
    targetLabDeviceId: labDevice.id,
    actorId: 'usr-inv-02',
    actorRole: 'INVESTIGATOR'
  });

  assert.strictEqual(simResult.isSimulated, true);
  assert.strictEqual(simResult.labEnvironmentBadge, 'CONTROLLED_LABORATORY_SYNTHETIC_DATA');
  assert.ok(simResult.evaluations.length >= 4, 'Must evaluate multiple browser and permission boundaries');

  const sopEvaluation = simResult.evaluations.find(e => e.boundary.includes('Same-Origin Policy'));
  assert.strictEqual(sopEvaluation.result, 'BLOCKED');
  assert.strictEqual(sopEvaluation.status, 'SECURE');
});

test('LabService: Strictly refuses to execute lab simulations on LIVE corporate endpoints', async () => {
  const liveDevice = db.prepare('SELECT id, device_name FROM devices WHERE is_lab_device = 0 LIMIT 1').get();
  assert.ok(liveDevice, 'Must have a live corporate device');

  await assert.rejects(
    async () => {
      await LabService.runScenario({
        scenarioId: 'scen-01',
        targetLabDeviceId: liveDevice.id,
        actorId: 'usr-inv-02'
      });
    },
    /SAFETY RESTRICTION.*LIVE corporate device/,
    'Must block execution on live endpoints'
  );
});
