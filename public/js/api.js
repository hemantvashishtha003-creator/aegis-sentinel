// API Client for AEGIS-Sentinel Backend

const API = {
  async get(url) {
    const res = await fetch(url);
    const data = await res.json();
    if (!res.ok || data.success === false) {
      throw new Error(data.error || 'Request failed');
    }
    return data.data !== undefined ? data.data : data;
  },

  async post(url, body) {
    const res = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body)
    });
    const data = await res.json();
    if (!res.ok || data.success === false) {
      throw new Error(data.error || 'Request failed');
    }
    return data.data !== undefined ? data.data : data;
  },

  async patch(url, body) {
    const res = await fetch(url, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body)
    });
    const data = await res.json();
    if (!res.ok || data.success === false) {
      throw new Error(data.error || 'Request failed');
    }
    return data.data !== undefined ? data.data : data;
  },

  // Stats & Users
  getDashboardStats() {
    return this.get('/api/stats/dashboard-stats');
  },
  getUsers() {
    return this.get('/api/users');
  },

  // 1. Device Access Assessment
  scanUrl(url, investigatorId, investigatorRole) {
    return this.post('/api/assessment/scan', { url, investigatorId, investigatorRole });
  },
  getAssessments(limit = 50) {
    return this.get(`/api/assessment?limit=${limit}`);
  },
  getAssessmentById(id) {
    return this.get(`/api/assessment/${id}`);
  },

  // 2. Authorized Forensic Evidence Vault
  acquireEvidence(payload) {
    return this.post('/api/evidence/acquire', payload);
  },
  getEvidenceList(incidentId) {
    const query = incidentId ? `?incidentId=${incidentId}` : '';
    return this.get(`/api/evidence${query}`);
  },
  getEvidenceDetail(id, actorId, actorRole) {
    return this.get(`/api/evidence/${id}?actorId=${actorId}&actorRole=${actorRole}`);
  },
  setLegalHold(id, legalHold, actorId, actorRole) {
    return this.patch(`/api/evidence/${id}/legal-hold`, { legalHold, actorId, actorRole });
  },
  purgeExpiredEvidence(actorId, actorRole) {
    return this.post('/api/evidence/purge-expired', { actorId, actorRole });
  },

  // 3. MDM Device Fleet & Remote Response
  getDevices(filter = {}) {
    const params = new URLSearchParams(filter).toString();
    return this.get(`/api/mdm/devices?${params}`);
  },
  getDeviceById(id) {
    return this.get(`/api/mdm/devices/${id}`);
  },
  enrollDevice(payload) {
    return this.post('/api/mdm/devices/enroll', payload);
  },
  quarantineDevice(deviceId, reason, actorId, actorRole) {
    return this.post('/api/mdm/quarantine', { deviceId, reason, actorId, actorRole });
  },
  lockDevice(deviceId, lockPin, customMessage, actorId, actorRole) {
    return this.post('/api/mdm/lock', { deviceId, lockPin, customMessage, actorId, actorRole });
  },
  initiateFactoryReset(deviceId, reason, incidentId, actorId, actorRole) {
    return this.post('/api/mdm/factory-reset/initiate', { deviceId, reason, incidentId, actorId, actorRole });
  },
  confirmFactoryReset(commandId, confirmationCode, dualApproverId, actorId, actorRole) {
    return this.post('/api/mdm/factory-reset/confirm', { commandId, confirmationCode, dualApproverId, actorId, actorRole });
  },
  getCommandHistory() {
    return this.get('/api/mdm/commands');
  },

  // 4. Isolated Security Testing Lab
  getLabScenarios() {
    return this.get('/api/lab/scenarios');
  },
  runLabScenario(scenarioId, targetLabDeviceId, actorId, actorRole) {
    return this.post('/api/lab/run', { scenarioId, targetLabDeviceId, actorId, actorRole });
  },

  // 5. Tamper-Evident Audit Trail
  getAuditLogs(limit = 100, eventType = null) {
    let url = `/api/audit/logs?limit=${limit}`;
    if (eventType) url += `&eventType=${eventType}`;
    return this.get(url);
  },
  verifyAuditChain() {
    return this.get('/api/audit/verify-chain');
  }
};

window.API = API;
