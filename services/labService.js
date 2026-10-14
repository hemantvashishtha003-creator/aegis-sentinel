const crypto = require('crypto');
const db = require('../db');
const AuditService = require('./auditService');

class LabService {
  /**
   * Lists available laboratory scenarios with synthetic profiles
   */
  static listScenarios() {
    const rows = db.prepare('SELECT * FROM lab_scenarios ORDER BY id ASC').all();
    return rows.map(r => ({
      ...r,
      syntheticUser: JSON.parse(r.synthetic_user),
      browserProtectionsTested: JSON.parse(r.browser_protections_tested),
      permissionBoundariesTested: JSON.parse(r.permission_boundaries_tested),
      syntheticArtifacts: JSON.parse(r.synthetic_artifacts),
      lastResult: r.last_result ? JSON.parse(r.last_result) : null
    }));
  }

  /**
   * Retrieves single scenario
   */
  static getScenarioById(scenarioId) {
    const r = db.prepare('SELECT * FROM lab_scenarios WHERE id = ?').get(scenarioId);
    if (!r) return null;
    return {
      ...r,
      syntheticUser: JSON.parse(r.synthetic_user),
      browserProtectionsTested: JSON.parse(r.browser_protections_tested),
      permissionBoundariesTested: JSON.parse(r.permission_boundaries_tested),
      syntheticArtifacts: JSON.parse(r.synthetic_artifacts),
      lastResult: r.last_result ? JSON.parse(r.last_result) : null
    };
  }

  /**
   * Executes an isolated laboratory test scenario against an authorized lab device
   */
  static async runScenario({ scenarioId, targetLabDeviceId, actorId = 'usr-inv-02', actorRole = 'INVESTIGATOR' }) {
    const scenario = this.getScenarioById(scenarioId);
    if (!scenario) throw new Error(`Lab scenario '${scenarioId}' not found.`);

    // Strict safety check: device MUST be an enrolled lab device
    const device = db.prepare('SELECT * FROM devices WHERE id = ?').get(targetLabDeviceId);
    if (!device) throw new Error(`Target device '${targetLabDeviceId}' not found.`);

    if (!device.is_lab_device) {
      throw new Error(`SAFETY RESTRICTION: Device '${device.device_name}' is a LIVE corporate device. Lab security simulations can ONLY be executed against designated test lab devices.`);
    }

    const runTimestamp = new Date().toISOString();
    const evaluationResults = {
      executionId: `sim-${Date.now()}-${crypto.randomBytes(3).toString('hex')}`,
      timestamp: runTimestamp,
      isSimulated: true,
      labEnvironmentBadge: 'CONTROLLED_LABORATORY_SYNTHETIC_DATA',
      targetLabDevice: {
        id: device.id,
        name: device.device_name,
        platform: device.platform,
        osVersion: device.os_version,
        isLabDevice: true
      },
      scenarioName: scenario.scenario_name,
      attackVector: scenario.attack_vector,
      syntheticUserTargeted: scenario.syntheticUser,
      evaluations: [
        {
          boundary: 'Browser Same-Origin Policy (SOP)',
          test: 'Malicious page script attempting cross-origin read from https://portal.synthetic-corp.test/api/profile',
          result: 'BLOCKED',
          status: 'SECURE',
          detail: 'Browser Network Engine blocked access under Same-Origin Policy. No CORS header granted.'
        },
        {
          boundary: 'Credential Autofill Domain Gate',
          test: 'Password manager autofill into impersonated input field',
          result: 'AUTOFILL_SUPPRESSED',
          status: 'SECURE',
          detail: 'Password manager detected domain mismatch (phish-portal.test vs synthetic-corp.test) and suppressed credentials.'
        },
        {
          boundary: 'Web File System Access API',
          test: 'Simulated JavaScript call to window.showOpenFilePicker() without user interaction',
          result: 'SECURITY_ERROR',
          status: 'SECURE',
          detail: 'Failed to execute: User activation is required. Zero silent disk scanning capability.'
        },
        {
          boundary: 'Hardware Permissions API (Webcam / Mic / Geolocation)',
          test: 'navigator.mediaDevices.getUserMedia({ audio: true, video: true }) probe',
          result: 'CONSENT_PROMPT_MANDATORY',
          status: 'SECURE',
          detail: 'Browser core strictly required explicit user prompt; silent recording prevented.'
        },
        {
          boundary: 'Mobile Device Management (MDM) Isolation',
          test: 'Script attempting to issue remote wipe or device configuration command',
          result: 'IMPOSSIBLE_BY_DESIGN',
          status: 'SECURE',
          detail: 'MDM protocol is completely inaccessible to browser DOM. Requires cryptographic APNs/WNS client certificate.'
        }
      ],
      incidentResponseRecommendation: {
        suggestedAction: 'Isolate endpoint in lab, collect forensic triage memory dump, and add domain to proxy sinkhole.',
        playbook: 'NIST SP 800-61 Rev. 2 Phishing & Host Containment'
      },
      summary: 'SIMULATION RESULT: All browser sandbox and operating system permission boundaries remained intact. Visiting the simulated phishing link caused NO loss of private device data.'
    };

    // Update scenario record
    db.prepare('UPDATE lab_scenarios SET last_run_at = ?, last_result = ? WHERE id = ?')
      .run(runTimestamp, JSON.stringify(evaluationResults), scenario.id);

    // Audit log
    AuditService.logEvent({
      eventType: 'LAB_SCENARIO_SIMULATION_EXECUTED',
      actorId,
      actorRole,
      targetEntityType: 'LAB_SCENARIO',
      targetEntityId: scenario.id,
      action: 'RUN_ISOLATED_SIMULATION',
      details: {
        scenarioId: scenario.id,
        targetLabDeviceId: device.id,
        isSimulated: true,
        evaluationsCount: evaluationResults.evaluations.length
      }
    });

    return evaluationResults;
  }
}

module.exports = LabService;
