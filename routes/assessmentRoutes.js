const express = require('express');
const router = express.Router();
const AssessmentService = require('../services/assessmentService');

// POST /api/assessment/scan - Perform Lawful URL and Security Boundary Assessment
router.post('/scan', async (req, res) => {
  try {
    const { url, investigatorId, investigatorRole } = req.body;
    if (!url) {
      return res.status(400).json({ success: false, error: 'URL parameter is required.' });
    }

    const result = await AssessmentService.assessUrl({
      url,
      investigatorId: investigatorId || 'usr-inv-02',
      investigatorRole: investigatorRole || 'INVESTIGATOR'
    });

    res.json({ success: true, data: result });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// GET /api/assessment - List past assessments
router.get('/', (req, res) => {
  try {
    const limit = parseInt(req.query.limit, 10) || 50;
    const offset = parseInt(req.query.offset, 10) || 0;
    const assessments = AssessmentService.getAssessments({ limit, offset });
    res.json({ success: true, data: assessments });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// GET /api/assessment/:id - Single assessment detail
router.get('/:id', (req, res) => {
  try {
    const assessment = AssessmentService.getAssessmentById(req.params.id);
    if (!assessment) {
      return res.status(404).json({ success: false, error: 'Assessment not found.' });
    }
    res.json({ success: true, data: assessment });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

module.exports = router;
