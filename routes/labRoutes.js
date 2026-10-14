const express = require('express');
const router = express.Router();
const LabService = require('../services/labService');

// GET /api/lab/scenarios - List laboratory scenarios
router.get('/scenarios', (req, res) => {
  try {
    const scenarios = LabService.listScenarios();
    res.json({ success: true, data: scenarios });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// GET /api/lab/scenarios/:id - Single scenario details
router.get('/scenarios/:id', (req, res) => {
  try {
    const scenario = LabService.getScenarioById(req.params.id);
    if (!scenario) {
      return res.status(404).json({ success: false, error: 'Scenario not found.' });
    }
    res.json({ success: true, data: scenario });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// POST /api/lab/run - Execute isolated laboratory simulation
router.post('/run', async (req, res) => {
  try {
    const { scenarioId, targetLabDeviceId, actorId, actorRole } = req.body;
    if (!scenarioId || !targetLabDeviceId) {
      return res.status(400).json({ success: false, error: 'scenarioId and targetLabDeviceId are required.' });
    }

    const result = await LabService.runScenario({
      scenarioId,
      targetLabDeviceId,
      actorId: actorId || 'usr-inv-02',
      actorRole: actorRole || 'INVESTIGATOR'
    });

    res.json({ success: true, data: result });
  } catch (error) {
    res.status(400).json({ success: false, error: error.message });
  }
});

module.exports = router;
