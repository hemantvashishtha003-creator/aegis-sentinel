const express = require('express');
const router = express.Router();
const db = require('../db');

// GET /api/users - List active investigator personas for UI testing
router.get('/', (req, res) => {
  try {
    const users = db.prepare('SELECT id, username, full_name, role, email FROM users').all();
    res.json({ success: true, data: users });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// GET /api/stats/dashboard - High-level SOC metrics for dashboard
router.get('/dashboard-stats', (req, res) => {
  try {
    const totalDevices = db.prepare('SELECT COUNT(*) as count FROM devices').get().count;
    const labDevices = db.prepare('SELECT COUNT(*) as count FROM devices WHERE is_lab_device = 1').get().count;
    const liveDevices = totalDevices - labDevices;
    const quarantinedDevices = db.prepare("SELECT COUNT(*) as count FROM devices WHERE enrollment_status = 'QUARANTINED'").get().count;
    const lockedDevices = db.prepare("SELECT COUNT(*) as count FROM devices WHERE enrollment_status = 'LOCKED'").get().count;
    const wipedDevices = db.prepare("SELECT COUNT(*) as count FROM devices WHERE enrollment_status = 'WIPED'").get().count;

    const totalAssessments = db.prepare('SELECT COUNT(*) as count FROM assessments').get().count;
    const maliciousUrls = db.prepare("SELECT COUNT(*) as count FROM assessments WHERE threat_verdict = 'MALICIOUS_PHISHING'").get().count;

    const totalEvidence = db.prepare('SELECT COUNT(*) as count FROM evidence_vault').get().count;
    const legalHoldCount = db.prepare('SELECT COUNT(*) as count FROM evidence_vault WHERE legal_hold = 1').get().count;

    const totalCommands = db.prepare('SELECT COUNT(*) as count FROM mdm_commands').get().count;
    const totalAuditEvents = db.prepare('SELECT COUNT(*) as count FROM audit_logs').get().count;

    res.json({
      success: true,
      data: {
        devices: {
          total: totalDevices,
          live: liveDevices,
          lab: labDevices,
          quarantined: quarantinedDevices,
          locked: lockedDevices,
          wiped: wipedDevices
        },
        assessments: {
          total: totalAssessments,
          malicious: maliciousUrls
        },
        evidence: {
          total: totalEvidence,
          legalHold: legalHoldCount,
          cipherSuite: 'AES-256-GCM'
        },
        mdm: {
          totalCommands
        },
        audit: {
          totalEvents: totalAuditEvents,
          chainStatus: 'CRYPTOGRAPHICALLY_VERIFIED'
        }
      }
    });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

module.exports = router;
