const express = require('express');
const router = express.Router();
const EvidenceService = require('../services/evidenceService');

// POST /api/evidence/acquire - Collect and encrypt evidence from an authorized device
router.post('/acquire', async (req, res) => {
  try {
    const { deviceId, incidentId, evidenceType, customNotes, retentionDays, actorId, actorRole } = req.body;
    if (!deviceId) {
      return res.status(400).json({ success: false, error: 'Target deviceId is required.' });
    }

    const result = await EvidenceService.acquireDeviceEvidence({
      deviceId,
      incidentId: incidentId || 'INC-2026-PHISH-01',
      evidenceType: evidenceType || 'BROWSER_LOG',
      actorId: actorId || 'usr-inv-02',
      actorRole: actorRole || 'INVESTIGATOR',
      customNotes: customNotes || '',
      retentionDays: retentionDays ? parseInt(retentionDays, 10) : 90
    });

    res.json({ success: true, data: result });
  } catch (error) {
    res.status(400).json({ success: false, error: error.message });
  }
});

// GET /api/evidence - List all evidence records (vault metadata)
router.get('/', (req, res) => {
  try {
    const incidentId = req.query.incidentId;
    const limit = parseInt(req.query.limit, 10) || 50;
    const offset = parseInt(req.query.offset, 10) || 0;

    const list = EvidenceService.listEvidence({ incidentId, limit, offset });
    res.json({ success: true, data: list });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// GET /api/evidence/:id - Get decrypted evidence detail (subject to RBAC)
router.get('/:id', (req, res) => {
  try {
    const actorId = req.query.actorId || 'usr-inv-02';
    const actorRole = req.query.actorRole || 'INVESTIGATOR';

    const detail = EvidenceService.getEvidenceDetail({
      evidenceId: req.params.id,
      actorId,
      actorRole
    });

    res.json({ success: true, data: detail });
  } catch (error) {
    res.status(404).json({ success: false, error: error.message });
  }
});

// PATCH /api/evidence/:id/legal-hold - Toggle legal hold
router.patch('/:id/legal-hold', (req, res) => {
  try {
    const { legalHold, actorId, actorRole } = req.body;
    const result = EvidenceService.setLegalHold({
      evidenceId: req.params.id,
      legalHold: Boolean(legalHold),
      actorId: actorId || 'usr-cmd-01',
      actorRole: actorRole || 'COMMANDER'
    });
    res.json({ success: true, data: result });
  } catch (error) {
    res.status(403).json({ success: false, error: error.message });
  }
});

// POST /api/evidence/purge-expired - Automated retention purge
router.post('/purge-expired', (req, res) => {
  try {
    const { actorId, actorRole } = req.body;
    const result = EvidenceService.purgeExpiredEvidence({
      actorId: actorId || 'usr-cmd-01',
      actorRole: actorRole || 'COMMANDER'
    });
    res.json({ success: true, data: result });
  } catch (error) {
    res.status(403).json({ success: false, error: error.message });
  }
});

module.exports = router;
