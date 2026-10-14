const test = require('node:test');
const assert = require('node:assert');
const AssessmentService = require('../services/assessmentService');

test('AssessmentService: Lawfully assesses URL and extracts public telemetry', async () => {
  const result = await AssessmentService.assessUrl({
    url: 'https://login.microsoftonline.com.phish-portal.test/auth?token=xyz998',
    investigatorId: 'usr-inv-02'
  });

  assert.ok(result.id, 'Assessment should have a generated ID');
  assert.strictEqual(result.domain, 'login.microsoftonline.com.phish-portal.test');
  assert.ok(result.riskScore > 50, 'Brand impersonation should raise risk score');
  assert.strictEqual(result.threatVerdict, 'MALICIOUS_PHISHING');

  // Verify Lawful DNS & TLS data
  assert.ok(result.lawfulData, 'Lawful data must be present');
  assert.strictEqual(result.lawfulData.protocol, 'https:');
  assert.ok(result.lawfulData.dns.aRecords.length > 0, 'DNS A records should be extracted or safely resolved');
  assert.ok(result.lawfulData.tls.isSecureHttps, 'TLS inspection should reflect https protocol');

  // Verify Security Boundary Analysis
  assert.ok(result.boundaryAnalysis, 'Boundary analysis must be present');
  assert.strictEqual(result.boundaryAnalysis.browserSandbox.permissionsApi.silentAccessPossible, false, 'Silent permission access must be impossible');
  assert.strictEqual(result.boundaryAnalysis.browserSandbox.fileSystemAccessApi.silentAccessPossible, false, 'Silent filesystem access must be impossible');
  assert.strictEqual(result.boundaryAnalysis.deviceManagementRequirements.canUrlTriggerMdmWipe, false, 'URL cannot trigger MDM wipe');
  assert.match(result.boundaryAnalysis.verdictStatement, /CRITICAL SECURITY BOUNDARY VERIFICATION/, 'Verdict statement must emphasize boundary guarantees');
});

test('AssessmentService: Detects raw IP address hostname with high threat score', async () => {
  const result = await AssessmentService.assessUrl({
    url: 'http://192.168.1.105/login-credential-capture',
    investigatorId: 'usr-inv-02'
  });

  assert.strictEqual(result.domain, '192.168.1.105');
  assert.ok(result.riskScore >= 60, 'Raw IP should trigger high risk score');
  const rawIpReason = result.reasons.find(r => r.code === 'RAW_IP_HOSTNAME');
  assert.ok(rawIpReason, 'Should report RAW_IP_HOSTNAME indicator');
});
