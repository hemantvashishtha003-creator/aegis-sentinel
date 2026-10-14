const express = require('express');
const router = express.Router();
const AuditService = require('../services/auditService');

// GET /api/audit/logs - List tamper-evident audit records
router.get('/logs', (req, res) => {
  try {
    const limit = parseInt(req.query.limit, 10) || 50;
    const offset = parseInt(req.query.offset, 10) || 0;
    const eventType = req.query.eventType || null;

    const logs = AuditService.getLogs({ limit, offset, eventType });
    res.json({ success: true, data: logs });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// GET /api/audit/verify-chain - Cryptographically verify hash integrity of the entire audit chain
router.get('/verify-chain', (req, res) => {
  try {
    const verification = AuditService.verifyChainIntegrity();
    res.json({ success: true, data: verification });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

module.exports = router;
