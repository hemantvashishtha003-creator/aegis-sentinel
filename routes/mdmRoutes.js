const express = require('express');
const router = express.Router();
const MdmService = require('../services/mdmService');

// GET /api/mdm/devices - List all managed endpoints (live and lab)
router.get('/devices', (req, res) => {
  try {
    const { platform, enrollmentStatus, isLabDevice } = req.query;
    const devices = MdmService.listDevices({ platform, enrollmentStatus, isLabDevice });
    res.json({ success: true, data: devices });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// GET /api/mdm/devices/:id - Single device detail
router.get('/devices/:id', (req, res) => {
  try {
    const device = MdmService.getDeviceById(req.params.id);
    if (!device) {
      return res.status(404).json({ success: false, error: 'Device not found.' });
    }
    res.json({ success: true, data: device });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// POST /api/mdm/devices/enroll - Enroll new managed device
router.post('/devices/enroll', (req, res) => {
  try {
    const { deviceName, serialNumber, platform, osVersion, assignedUser, isLabDevice, hardwareModel, actorId, actorRole } = req.body;
    const device = MdmService.enrollDevice({
      deviceName,
      serialNumber,
      platform,
      osVersion,
      assignedUser,
      isLabDevice: Number(isLabDevice) || 0,
      hardwareModel,
      actorId: actorId || 'usr-cmd-01',
      actorRole: actorRole || 'COMMANDER'
    });
    res.status(201).json({ success: true, data: device });
  } catch (error) {
    res.status(400).json({ success: false, error: error.message });
  }
});

// POST /api/mdm/quarantine - Network isolate device
router.post('/quarantine', async (req, res) => {
  try {
    const { deviceId, actorId, actorRole, reason } = req.body;
    const result = await MdmService.quarantineDevice({
      deviceId,
      actorId: actorId || 'usr-inv-02',
      actorRole: actorRole || 'INVESTIGATOR',
      reason: reason || 'Incident Response Isolation'
    });
    res.json({ success: true, data: result });
  } catch (error) {
    res.status(400).json({ success: false, error: error.message });
  }
});

// POST /api/mdm/lock - Remote lock device
router.post('/lock', async (req, res) => {
  try {
    const { deviceId, lockPin, customMessage, actorId, actorRole, reason } = req.body;
    const result = await MdmService.remoteLock({
      deviceId,
      lockPin: lockPin || '739104',
      customMessage,
      actorId: actorId || 'usr-inv-02',
      actorRole: actorRole || 'INVESTIGATOR',
      reason: reason || 'Incident Response Remote Lock'
    });
    res.json({ success: true, data: result });
  } catch (error) {
    res.status(400).json({ success: false, error: error.message });
  }
});

// POST /api/mdm/factory-reset/initiate - Phase 1: Initiate Destructive Factory Reset
router.post('/factory-reset/initiate', (req, res) => {
  try {
    const { deviceId, actorId, actorRole, reason, incidentId } = req.body;
    const result = MdmService.initiateFactoryReset({
      deviceId,
      actorId: actorId || 'usr-cmd-01',
      actorRole: actorRole || 'COMMANDER',
      reason,
      incidentId: incidentId || 'INC-2026-PHISH-01'
    });
    res.json({ success: true, data: result });
  } catch (error) {
    res.status(400).json({ success: false, error: error.message });
  }
});

// POST /api/mdm/factory-reset/confirm - Phase 2: Confirm and Execute Destructive Reset
router.post('/factory-reset/confirm', (req, res) => {
  try {
    const { commandId, confirmationCode, dualApproverId, actorId, actorRole } = req.body;
    const result = MdmService.confirmFactoryReset({
      commandId,
      confirmationCode,
      dualApproverId,
      actorId: actorId || 'usr-cmd-01',
      actorRole: actorRole || 'COMMANDER'
    });
    res.json({ success: true, data: result });
  } catch (error) {
    res.status(400).json({ success: false, error: error.message });
  }
});

// GET /api/mdm/commands - View MDM command audit records
router.get('/commands', (req, res) => {
  try {
    const limit = parseInt(req.query.limit, 10) || 50;
    const offset = parseInt(req.query.offset, 10) || 0;
    const commands = MdmService.getCommandHistory({ limit, offset });
    res.json({ success: true, data: commands });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

module.exports = router;
