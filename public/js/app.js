// AEGIS-SENTINEL: Application Controller & State Engine

const State = {
  activeTab: 'dashboard',
  currentUser: {
    id: 'usr-inv-02',
    name: 'Elena Chen',
    role: 'INVESTIGATOR'
  },
  users: [],
  devices: [],
  selectedDeviceForReset: null,
  pendingResetCommand: null,
  stats: null
};

// Utilities
function showToast(message, type = 'info') {
  const container = document.getElementById('toast-container');
  if (!container) return;

  const toast = document.createElement('div');
  toast.className = `toast toast-${type}`;
  toast.innerHTML = `
    <span class="pulse-dot" style="background: ${type === 'error' ? 'var(--accent-crimson)' : (type === 'success' ? 'var(--accent-green)' : 'var(--accent-cyan)')}"></span>
    <span>${message}</span>
  `;

  container.appendChild(toast);
  setTimeout(() => {
    toast.style.opacity = '0';
    toast.style.transform = 'translateX(50px)';
    setTimeout(() => toast.remove(), 300);
  }, 4000);
}

function formatDate(isoStr) {
  if (!isoStr) return 'N/A';
  try {
    const d = new Date(isoStr);
    return d.toLocaleString('en-US', {
      month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit', second: '2-digit'
    });
  } catch {
    return isoStr;
  }
}

// Initialize Application
document.addEventListener('DOMContentLoaded', async () => {
  setupNavigation();
  await loadUserPersonas();
  setupEventListeners();
  loadDashboardData();
});

// Setup Navigation Tabs
function setupNavigation() {
  const navTabs = document.querySelectorAll('.nav-tab');
  navTabs.forEach(tab => {
    tab.addEventListener('click', () => {
      const targetView = tab.getAttribute('data-view');
      switchView(targetView);
    });
  });
}

function switchView(viewName) {
  State.activeTab = viewName;
  document.querySelectorAll('.nav-tab').forEach(t => {
    t.classList.toggle('active', t.getAttribute('data-view') === viewName);
  });
  document.querySelectorAll('.view-section').forEach(s => {
    s.classList.toggle('active', s.id === `view-${viewName}`);
  });

  // Trigger view load
  switch (viewName) {
    case 'dashboard':
      loadDashboardData();
      break;
    case 'assessment':
      loadAssessmentsHistory();
      break;
    case 'evidence':
      loadEvidenceVault();
      break;
    case 'mdm':
      loadMdmFleet();
      break;
    case 'lab':
      loadLabScenarios();
      break;
    case 'audit':
      loadAuditLogs();
      break;
  }
}

// Load and Switch User Personas (for easy RBAC testing)
async function loadUserPersonas() {
  try {
    const users = await API.getUsers();
    State.users = users;
    const select = document.getElementById('persona-select');
    if (!select) return;

    select.innerHTML = '';
    users.forEach(u => {
      const opt = document.createElement('option');
      opt.value = u.id;
      opt.textContent = `${u.full_name} (${u.role})`;
      if (u.id === State.currentUser.id) opt.selected = true;
      select.appendChild(opt);
    });

    select.addEventListener('change', (e) => {
      const selected = State.users.find(u => u.id === e.target.value);
      if (selected) {
        State.currentUser = {
          id: selected.id,
          name: selected.full_name,
          role: selected.role
        };
        showToast(`Switched active operator persona to ${selected.full_name} [${selected.role}]`, 'info');
        // Refresh active view to reflect RBAC permissions
        switchView(State.activeTab);
      }
    });
  } catch (err) {
    console.error('Failed to load personas:', err);
  }
}

// Event Listeners for Forms & Modals
function setupEventListeners() {
  // Assessment URL Scan Form
  const scanBtn = document.getElementById('btn-run-scan');
  const urlInput = document.getElementById('input-scan-url');
  if (scanBtn && urlInput) {
    scanBtn.addEventListener('click', () => runUrlScan(urlInput.value));
    urlInput.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') runUrlScan(urlInput.value);
    });
  }

  // Quick URL sample chips
  document.querySelectorAll('.sample-chip').forEach(chip => {
    chip.addEventListener('click', () => {
      const sampleUrl = chip.getAttribute('data-url');
      if (urlInput) {
        urlInput.value = sampleUrl;
        runUrlScan(sampleUrl);
      }
    });
  });

  // Modal Closers
  document.querySelectorAll('.modal-close-btn, .btn-modal-cancel').forEach(btn => {
    btn.addEventListener('click', closeModal);
  });

  // Modal Backdrops
  document.querySelectorAll('.modal-backdrop').forEach(backdrop => {
    backdrop.addEventListener('click', (e) => {
      if (e.target === backdrop) closeModal();
    });
  });

  // Dual-Auth Factory Reset Step 1: Initiate
  const btnInitReset = document.getElementById('btn-initiate-reset-step');
  if (btnInitReset) {
    btnInitReset.addEventListener('click', handleInitiateFactoryReset);
  }

  // Dual-Auth Factory Reset Step 2: Confirm
  const btnConfirmReset = document.getElementById('btn-execute-confirmed-reset');
  if (btnConfirmReset) {
    btnConfirmReset.addEventListener('click', handleConfirmFactoryReset);
  }

  // Verify Audit Chain Button
  const btnVerifyChain = document.getElementById('btn-verify-chain');
  if (btnVerifyChain) {
    btnVerifyChain.addEventListener('click', handleVerifyAuditChain);
  }

  // Purge Expired Evidence Button
  const btnPurgeEvidence = document.getElementById('btn-purge-evidence');
  if (btnPurgeEvidence) {
    btnPurgeEvidence.addEventListener('click', handlePurgeEvidence);
  }

  // Device Enrollment Form Submit
  const formEnroll = document.getElementById('form-enroll-device');
  if (formEnroll) {
    formEnroll.addEventListener('submit', handleEnrollDeviceSubmit);
  }

  // Evidence Acquisition Form Submit
  const formAcquire = document.getElementById('form-acquire-evidence');
  if (formAcquire) {
    formAcquire.addEventListener('submit', handleAcquireEvidenceSubmit);
  }
}

function closeModal() {
  document.querySelectorAll('.modal-backdrop').forEach(m => m.classList.remove('active'));
}

function openModal(modalId) {
  const modal = document.getElementById(modalId);
  if (modal) modal.classList.add('active');
}

// ====================================================================
// 1. DASHBOARD CONTROLLER
// ====================================================================
async function loadDashboardData() {
  try {
    const stats = await API.getDashboardStats();
    State.stats = stats;

    document.getElementById('stat-total-devices').textContent = stats.devices.total;
    document.getElementById('stat-quarantined').textContent = stats.devices.quarantined + stats.devices.locked;
    document.getElementById('stat-assessments').textContent = stats.assessments.total;
    document.getElementById('stat-vault-items').textContent = stats.evidence.total;
    document.getElementById('stat-audit-count').textContent = stats.audit.totalEvents;

    // Load active devices summary table
    const devices = await API.getDevices();
    State.devices = devices;
    const tbody = document.getElementById('dashboard-devices-tbody');
    if (tbody) {
      tbody.innerHTML = '';
      devices.slice(0, 5).forEach(d => {
        const tr = document.createElement('tr');
        tr.innerHTML = `
          <td>
            <strong>${d.device_name}</strong><br>
            <span class="code-inline">${d.serial_number}</span>
          </td>
          <td>
            <span class="badge ${d.is_lab_device ? 'badge-lab' : 'badge-corp'}">
              ${d.is_lab_device ? 'LAB TEST RANGE' : 'CORP MANAGED'}
            </span>
          </td>
          <td>${d.platform.toUpperCase()} (${d.os_version})</td>
          <td>
            <span class="badge badge-${d.enrollment_status.toLowerCase()}">${d.enrollment_status}</span>
          </td>
          <td>${formatDate(d.last_seen)}</td>
        `;
        tbody.appendChild(tr);
      });
    }

    // Load recent assessments
    const assessments = await API.getAssessments(5);
    const asmList = document.getElementById('dashboard-assessments-list');
    if (asmList) {
      asmList.innerHTML = '';
      if (assessments.length === 0) {
        asmList.innerHTML = '<p class="text-secondary" style="padding:1rem;">No URL assessments recorded yet. Run a scan from the assessment tab.</p>';
      } else {
        assessments.forEach(a => {
          const item = document.createElement('div');
          item.className = 'reason-item';
          item.innerHTML = `
            <span class="reason-severity ${a.threat_verdict === 'MALICIOUS_PHISHING' ? 'sev-critical' : (a.threat_verdict === 'SUSPICIOUS' ? 'sev-medium' : 'sev-low')}">
              ${a.threat_verdict}
            </span>
            <div class="reason-info" style="flex:1;">
              <div class="reason-code">${a.domain}</div>
              <div class="reason-desc">${a.target_url} &bull; Risk Score: <strong>${a.risk_score}/100</strong> &bull; ${formatDate(a.created_at)}</div>
            </div>
          `;
          asmList.appendChild(item);
        });
      }
    }
  } catch (err) {
    console.error('Error loading dashboard stats:', err);
  }
}

// ====================================================================
// 2. DEVICE ACCESS ASSESSMENT CONTROLLER
// ====================================================================
async function runUrlScan(url) {
  if (!url || !url.trim()) {
    showToast('Please enter a target URL to evaluate.', 'error');
    return;
  }

  const scanBtn = document.getElementById('btn-run-scan');
  scanBtn.disabled = true;
  scanBtn.innerHTML = '<span class="pulse-dot"></span> Analyzing Boundaries...';

  try {
    const result = await API.scanUrl(url.trim(), State.currentUser.id, State.currentUser.role);
    renderAssessmentResult(result);
    showToast(`Assessment complete for ${result.domain}. Verdict: ${result.threatVerdict}`, 'success');
    loadAssessmentsHistory();
  } catch (err) {
    showToast(`Scan failed: ${err.message}`, 'error');
  } finally {
    scanBtn.disabled = false;
    scanBtn.innerHTML = `
      <svg viewBox="0 0 24 24" fill="none" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
        <circle cx="11" cy="11" r="8"></circle>
        <line x1="21" y1="21" x2="16.65" y2="16.65"></line>
      </svg>
      Assess Boundaries & Public Intel
    `;
  }
}

function renderAssessmentResult(res) {
  const container = document.getElementById('assessment-result-container');
  if (!container) return;
  container.style.display = 'block';

  // Risk Score & Verdict Pill
  const verdictBadge = document.getElementById('res-verdict-badge');
  verdictBadge.textContent = `${res.threatVerdict} (Risk: ${res.riskScore}/100)`;
  verdictBadge.className = `badge ${res.threatVerdict === 'MALICIOUS_PHISHING' ? 'badge-malicious' : (res.threatVerdict === 'SUSPICIOUS' ? 'badge-quarantined' : 'badge-secure')}`;

  document.getElementById('res-domain').textContent = res.domain;
  document.getElementById('res-url').textContent = res.targetUrl;

  // Verdict statement
  document.getElementById('res-verdict-statement').textContent = res.boundaryAnalysis.verdictStatement;

  // Browser Boundaries Matrix
  const b = res.boundaryAnalysis.browserSandbox;
  document.getElementById('res-sop-desc').textContent = b.sameOriginPolicy.description;
  document.getElementById('res-cookie-desc').textContent = b.cookieIsolation.description;
  document.getElementById('res-perm-desc').textContent = b.permissionsApi.description;
  document.getElementById('res-fs-desc').textContent = b.fileSystemAccessApi.description;

  // OS & MDM Isolation
  const os = res.boundaryAnalysis.operatingSystemPermissions;
  const mdm = res.boundaryAnalysis.deviceManagementRequirements;
  document.getElementById('res-os-sandbox-desc').textContent = `${os.rendererProcessSandboxing.mechanism}: ${os.rendererProcessSandboxing.impact}`;
  document.getElementById('res-mdm-desc').textContent = mdm.explanation;

  // DNS & TLS Public Intel
  const lawful = res.lawfulData;
  document.getElementById('res-dns-ips').textContent = lawful.dns.aRecords.join(', ') || 'None';
  document.getElementById('res-tls-proto').textContent = `${lawful.tls.protocol} | Cipher: ${lawful.tls.cipherSuite}`;
  document.getElementById('res-tls-issuer').textContent = lawful.tls.issuer;

  // HTTP Security Headers
  const h = lawful.headers;
  document.getElementById('res-hdr-csp').textContent = h.contentSecurityPolicy.present ? 'Present' : 'MISSING (Fails to restrict script origin)';
  document.getElementById('res-hdr-hsts').textContent = h.strictTransportSecurity.value;
  document.getElementById('res-hdr-xframe').textContent = h.xFrameOptions.status;

  // Indicators List
  const reasonsContainer = document.getElementById('res-reasons-list');
  reasonsContainer.innerHTML = '';
  if (res.reasons.length === 0) {
    reasonsContainer.innerHTML = '<p class="text-secondary" style="font-size:0.85rem;">No suspicious behavioral phishing indicators detected.</p>';
  } else {
    res.reasons.forEach(r => {
      const item = document.createElement('div');
      item.className = 'reason-item';
      item.innerHTML = `
        <span class="reason-severity ${r.severity === 'CRITICAL' ? 'sev-critical' : (r.severity === 'HIGH' ? 'sev-high' : 'sev-medium')}">${r.severity}</span>
        <div class="reason-info">
          <div class="reason-code">${r.code}</div>
          <div class="reason-desc">${r.description}</div>
        </div>
      `;
      reasonsContainer.appendChild(item);
    });
  }

  // Smooth scroll into results
  container.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

async function loadAssessmentsHistory() {
  try {
    const list = await API.getAssessments(20);
    const tbody = document.getElementById('assessments-history-tbody');
    if (!tbody) return;

    tbody.innerHTML = '';
    list.forEach(a => {
      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td><strong>${a.domain}</strong><br><span class="code-inline" style="font-size:0.72rem;">${a.target_url}</span></td>
        <td>
          <span class="badge ${a.threat_verdict === 'MALICIOUS_PHISHING' ? 'badge-malicious' : (a.threat_verdict === 'SUSPICIOUS' ? 'badge-quarantined' : 'badge-secure')}">
            ${a.threat_verdict} (${a.risk_score})
          </span>
        </td>
        <td><span class="code-inline">${a.investigator_id}</span></td>
        <td>${formatDate(a.created_at)}</td>
        <td>
          <button class="btn btn-outline" style="padding:0.25rem 0.6rem; font-size:0.75rem;" onclick="viewPastAssessment('${a.id}')">
            View Analysis
          </button>
        </td>
      `;
      tbody.appendChild(tr);
    });
  } catch (err) {
    console.error('Error loading assessment history:', err);
  }
}

window.viewPastAssessment = async function(id) {
  try {
    const assessment = await API.getAssessmentById(id);
    renderAssessmentResult(assessment);
  } catch (err) {
    showToast(`Error viewing assessment: ${err.message}`, 'error');
  }
};

// ====================================================================
// 3. AUTHORIZED EVIDENCE VAULT CONTROLLER
// ====================================================================
async function loadEvidenceVault() {
  try {
    const list = await API.getEvidenceList();
    const tbody = document.getElementById('evidence-vault-tbody');
    if (!tbody) return;

    tbody.innerHTML = '';
    if (list.length === 0) {
      tbody.innerHTML = '<tr><td colspan="7" style="text-align:center; padding:2rem; color:var(--text-secondary);">No evidence collected yet. Use "Acquire Authorized Evidence" button.</td></tr>';
      return;
    }

    list.forEach(item => {
      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td>
          <strong>${item.title}</strong><br>
          <span class="code-inline" style="font-size:0.72rem;">${item.id}</span>
        </td>
        <td>
          <span class="badge badge-corp">${item.evidence_type}</span>
        </td>
        <td>
          <span class="code-inline" style="font-size:0.72rem;">${item.sha256_checksum.slice(0, 16)}...</span>
        </td>
        <td>${(item.file_size_bytes / 1024).toFixed(2)} KB</td>
        <td>
          <button class="btn ${item.legalHold ? 'btn-amber' : 'btn-outline'}" style="padding:0.2rem 0.5rem; font-size:0.72rem;" onclick="toggleLegalHold('${item.id}', ${!item.legalHold})">
            ${item.legalHold ? '🔒 LEGAL HOLD ON' : 'HOLD OFF'}
          </button>
        </td>
        <td>${formatDate(item.expires_at)}</td>
        <td>
          <button class="btn btn-cyan" style="padding:0.3rem 0.75rem; font-size:0.75rem;" onclick="inspectEvidenceModal('${item.id}')">
            Inspect & Decrypt
          </button>
        </td>
      `;
      tbody.appendChild(tr);
    });
  } catch (err) {
    console.error('Error loading evidence vault:', err);
  }
}

window.toggleLegalHold = async function(evidenceId, newStatus) {
  try {
    await API.setLegalHold(evidenceId, newStatus, State.currentUser.id, State.currentUser.role);
    showToast(`Legal Hold ${newStatus ? 'ENABLED' : 'DISABLED'} for ${evidenceId}`, 'success');
    loadEvidenceVault();
  } catch (err) {
    showToast(`Failed: ${err.message}`, 'error');
  }
};

window.inspectEvidenceModal = async function(evidenceId) {
  try {
    const detail = await API.getEvidenceDetail(evidenceId, State.currentUser.id, State.currentUser.role);
    
    document.getElementById('evd-modal-title').textContent = detail.title;
    document.getElementById('evd-modal-id').textContent = detail.id;
    document.getElementById('evd-modal-checksum').textContent = detail.sha256Checksum;
    document.getElementById('evd-modal-size').textContent = `${detail.fileSizeBytes} bytes`;
    document.getElementById('evd-modal-collector').textContent = `${detail.collectedBy} at ${formatDate(detail.collectedAt)}`;
    document.getElementById('evd-modal-expires').textContent = formatDate(detail.expiresAt);

    const jsonViewer = document.getElementById('evd-modal-content');
    const integrityPill = document.getElementById('evd-integrity-pill');

    if (detail.accessRestricted) {
      integrityPill.textContent = 'RESTRICTED (RBAC)';
      integrityPill.className = 'badge badge-locked';
      jsonViewer.textContent = JSON.stringify({
        error: 'ACCESS DENIED',
        reason: detail.message,
        requiredRoles: ['COMMANDER', 'INVESTIGATOR'],
        activeRole: State.currentUser.role,
        checksumGuaranteed: detail.sha256Checksum
      }, null, 2);
    } else {
      integrityPill.textContent = detail.checksumValid ? 'INTEGRITY VERIFIED (SHA-256 MATCH)' : 'CHECKSUM MISMATCH';
      integrityPill.className = `badge ${detail.checksumValid ? 'badge-secure' : 'badge-malicious'}`;
      jsonViewer.textContent = JSON.stringify(detail.decryptedContent, null, 2);
    }

    openModal('modal-evidence-detail');
  } catch (err) {
    showToast(`Error opening evidence: ${err.message}`, 'error');
  }
};

async function handlePurgeEvidence() {
  if (State.currentUser.role !== 'COMMANDER') {
    showToast('Permission Denied: Only COMMANDER role can initiate retention purge.', 'error');
    return;
  }
  if (!confirm('Execute automated retention policy purge on all expired evidence records not protected by Legal Hold?')) {
    return;
  }
  try {
    const res = await API.purgeExpiredEvidence(State.currentUser.id, State.currentUser.role);
    showToast(`Purge complete: ${res.purgedCount} expired items deleted.`, 'info');
    loadEvidenceVault();
  } catch (err) {
    showToast(`Purge failed: ${err.message}`, 'error');
  }
}

// Open Manual Evidence Acquisition Modal
window.openAcquisitionModal = function() {
  const select = document.getElementById('acq-device-select');
  if (select && State.devices) {
    select.innerHTML = '';
    State.devices.forEach(d => {
      const opt = document.createElement('option');
      opt.value = d.id;
      opt.textContent = `${d.device_name} [${d.is_lab_device ? 'LAB' : 'CORP'}] (${d.serial_number})`;
      select.appendChild(opt);
    });
  }
  openModal('modal-acquire-evidence');
};

async function handleAcquireEvidenceSubmit(e) {
  e.preventDefault();
  const deviceId = document.getElementById('acq-device-select').value;
  const evidenceType = document.getElementById('acq-evidence-type').value;
  const incidentId = document.getElementById('acq-incident-id').value;
  const customNotes = document.getElementById('acq-notes').value;

  try {
    const res = await API.acquireEvidence({
      deviceId,
      evidenceType,
      incidentId,
      customNotes,
      actorId: State.currentUser.id,
      actorRole: State.currentUser.role
    });

    closeModal();
    showToast(`Forensic evidence acquired & encrypted with AES-256-GCM. ID: ${res.evidenceId}`, 'success');
    loadEvidenceVault();
  } catch (err) {
    showToast(`Acquisition failed: ${err.message}`, 'error');
  }
}

// ====================================================================
// 4. MDM FLEET & REMOTE INCIDENT RESPONSE
// ====================================================================
async function loadMdmFleet() {
  try {
    const devices = await API.getDevices();
    State.devices = devices;
    const tbody = document.getElementById('mdm-devices-tbody');
    if (!tbody) return;

    tbody.innerHTML = '';
    devices.forEach(d => {
      const isLab = Boolean(d.is_lab_device);
      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td>
          <strong>${d.device_name}</strong><br>
          <span class="code-inline" style="font-size:0.72rem;">${d.serial_number}</span>
        </td>
        <td>
          <span class="badge ${isLab ? 'badge-lab' : 'badge-corp'}">
            ${isLab ? '🧪 SIMULATED LAB DEVICE' : '🛡️ VERIFIED MDM ENROLLED'}
          </span>
        </td>
        <td>
          <strong>${d.platform.toUpperCase()}</strong><br>
          <span style="font-size:0.75rem; color:var(--text-secondary);">${d.os_version}</span>
        </td>
        <td>
          <span class="badge badge-${d.enrollment_status.toLowerCase()}">${d.enrollment_status}</span>
        </td>
        <td>
          <span style="font-size:0.78rem;">${d.assigned_user}</span><br>
          <span class="code-inline" style="font-size:0.7rem;">${d.ip_address}</span>
        </td>
        <td>
          <div style="display:flex; gap:0.4rem; flex-wrap:wrap;">
            <button class="btn btn-amber" style="padding:0.25rem 0.6rem; font-size:0.72rem;" onclick="quarantineDevicePrompt('${d.id}')" ${d.enrollment_status === 'WIPED' ? 'disabled' : ''}>
              Quarantine
            </button>
            <button class="btn btn-outline" style="padding:0.25rem 0.6rem; font-size:0.72rem;" onclick="remoteLockPrompt('${d.id}')" ${d.enrollment_status === 'WIPED' ? 'disabled' : ''}>
              Remote Lock
            </button>
            <button class="btn btn-danger" style="padding:0.25rem 0.6rem; font-size:0.72rem;" onclick="startFactoryResetModal('${d.id}')" ${d.enrollment_status === 'WIPED' ? 'disabled' : ''}>
              Factory Reset
            </button>
          </div>
        </td>
      `;
      tbody.appendChild(tr);
    });

    // Also load recent commands history
    const commands = await API.getCommandHistory();
    const cmdTbody = document.getElementById('mdm-commands-tbody');
    if (cmdTbody) {
      cmdTbody.innerHTML = '';
      commands.slice(0, 10).forEach(cmd => {
        const tr = document.createElement('tr');
        tr.innerHTML = `
          <td><span class="code-inline" style="font-size:0.72rem;">${cmd.id}</span></td>
          <td><strong>${cmd.command_type}</strong></td>
          <td>${cmd.operator_id} [${cmd.operator_role}]</td>
          <td><span class="badge ${cmd.status === 'EXECUTED' ? 'badge-secure' : 'badge-quarantined'}">${cmd.status}</span></td>
          <td><span class="code-inline" style="font-size:0.7rem;">${cmd.signature_hash.slice(0, 16)}...</span></td>
          <td>${formatDate(cmd.created_at)}</td>
        `;
        cmdTbody.appendChild(tr);
      });
    }
  } catch (err) {
    console.error('Error loading MDM fleet:', err);
  }
}

window.quarantineDevicePrompt = async function(deviceId) {
  const reason = prompt('Enter operational reason for network quarantine (isolating to remediation VPN):', 'Phishing URL containment');
  if (!reason) return;

  try {
    const res = await API.quarantineDevice(deviceId, reason, State.currentUser.id, State.currentUser.role);
    showToast(`Device quarantined. HMAC: ${res.signature.slice(0, 12)}...`, 'success');
    loadMdmFleet();
  } catch (err) {
    showToast(`Quarantine failed: ${err.message}`, 'error');
  }
};

window.remoteLockPrompt = async function(deviceId) {
  const customMessage = prompt('Enter lock screen message:', 'This device has been locked by corporate security due to an active phishing investigation.');
  if (customMessage === null) return;

  try {
    const res = await API.lockDevice(deviceId, '841029', customMessage, State.currentUser.id, State.currentUser.role);
    showToast(`Remote Lock command sent to MDM agent. Status: ${res.status}`, 'success');
    loadMdmFleet();
  } catch (err) {
    showToast(`Remote lock failed: ${err.message}`, 'error');
  }
};

// Open Destructive Factory Reset Modal Flow
window.startFactoryResetModal = function(deviceId) {
  const device = State.devices.find(d => d.id === deviceId);
  if (!device) return;

  State.selectedDeviceForReset = device;
  State.pendingResetCommand = null;

  // Populate Step 1
  document.getElementById('reset-target-device-name').textContent = `${device.device_name} (${device.serial_number})`;
  document.getElementById('reset-target-badge').textContent = device.is_lab_device ? 'SIMULATED LAB ENVIRONMENT' : 'LIVE CORPORATE MANAGED DEVICE';
  document.getElementById('reset-target-badge').className = `badge ${device.is_lab_device ? 'badge-lab' : 'badge-corp'}`;
  document.getElementById('reset-operator-display').textContent = `${State.currentUser.name} [${State.currentUser.role}]`;

  // Reset steps visibility
  document.getElementById('reset-step-1').style.display = 'block';
  document.getElementById('reset-step-2').style.display = 'none';
  document.getElementById('reset-step-3-result').style.display = 'none';

  // Enable/disable dual approver field for lab vs live
  const dualApproverGroup = document.getElementById('reset-dual-approver-group');
  if (dualApproverGroup) {
    dualApproverGroup.style.display = device.is_lab_device ? 'none' : 'block';
  }

  openModal('modal-factory-reset');
};

async function handleInitiateFactoryReset() {
  const reason = document.getElementById('reset-reason-input').value;
  if (!reason || reason.trim().length < 10) {
    showToast('Please provide an operational reason of at least 10 characters.', 'error');
    return;
  }

  try {
    const result = await API.initiateFactoryReset(
      State.selectedDeviceForReset.id,
      reason.trim(),
      'INC-2026-PHISH-01',
      State.currentUser.id,
      State.currentUser.role
    );

    State.pendingResetCommand = result;

    // Transition to Step 2
    document.getElementById('reset-step-1').style.display = 'none';
    document.getElementById('reset-step-2').style.display = 'block';

    document.getElementById('reset-generated-code').textContent = result.confirmationCode;
    document.getElementById('reset-input-code').value = '';

    // Populate dual approver select (must be distinct from current operator)
    const dualSelect = document.getElementById('reset-dual-approver-select');
    if (dualSelect) {
      dualSelect.innerHTML = '';
      State.users
        .filter(u => u.id !== State.currentUser.id && ['COMMANDER', 'INVESTIGATOR'].includes(u.role))
        .forEach(u => {
          const opt = document.createElement('option');
          opt.value = u.id;
          opt.textContent = `${u.full_name} (${u.role})`;
          dualSelect.appendChild(opt);
        });
    }

    showToast('Factory reset initiated. Confirmation code generated.', 'info');
  } catch (err) {
    showToast(`Initiation failed: ${err.message}`, 'error');
  }
}

async function handleConfirmFactoryReset() {
  if (!State.pendingResetCommand) return;

  const enteredCode = document.getElementById('reset-input-code').value.trim();
  const dualSelect = document.getElementById('reset-dual-approver-select');
  const dualApproverId = dualSelect ? dualSelect.value : null;

  try {
    const res = await API.confirmFactoryReset(
      State.pendingResetCommand.commandId,
      enteredCode,
      dualApproverId,
      State.currentUser.id,
      State.currentUser.role
    );

    // Show Step 3 Success
    document.getElementById('reset-step-2').style.display = 'none';
    document.getElementById('reset-step-3-result').style.display = 'block';

    document.getElementById('reset-disclaimer-text').textContent = res.executionResult.simulationDisclaimer;
    document.getElementById('reset-signature-text').textContent = res.executionSignature;

    showToast('Factory reset command executed & cryptographically signed.', 'success');
    loadMdmFleet();
  } catch (err) {
    showToast(`Execution failed: ${err.message}`, 'error');
  }
}

// Device Enrollment Form Submit
async function handleEnrollDeviceSubmit(e) {
  e.preventDefault();
  const deviceName = document.getElementById('enroll-device-name').value;
  const serialNumber = document.getElementById('enroll-serial').value;
  const platform = document.getElementById('enroll-platform').value;
  const osVersion = document.getElementById('enroll-os').value;
  const assignedUser = document.getElementById('enroll-user').value;
  const isLabDevice = parseInt(document.getElementById('enroll-is-lab').value, 10);

  try {
    const dev = await API.enrollDevice({
      deviceName,
      serialNumber,
      platform,
      osVersion,
      assignedUser,
      isLabDevice,
      actorId: State.currentUser.id,
      actorRole: State.currentUser.role
    });

    closeModal();
    showToast(`Device '${dev.device_name}' enrolled with MDM token & certificate fingerprint.`, 'success');
    loadMdmFleet();
  } catch (err) {
    showToast(`Enrollment failed: ${err.message}`, 'error');
  }
}

// ====================================================================
// 5. ISOLATED CYBER RANGE TESTING LAB
// ====================================================================
async function loadLabScenarios() {
  try {
    const scenarios = await API.getLabScenarios();
    const container = document.getElementById('lab-scenarios-container');
    if (!container) return;

    container.innerHTML = '';
    scenarios.forEach(scen => {
      const card = document.createElement('div');
      card.className = 'scenario-card';
      card.innerHTML = `
        <div>
          <div class="scenario-header">
            <div>
              <span class="badge badge-lab" style="margin-bottom:0.4rem;">LAB SIMULATION</span>
              <div class="scenario-title">${scen.scenario_name}</div>
            </div>
            <span class="code-inline" style="font-size:0.7rem;">${scen.category}</span>
          </div>
          <div class="scenario-desc">${scen.description}</div>
          <div class="scenario-meta">
            <div class="meta-row">
              <span>Attack Vector:</span>
              <span>${scen.attack_vector}</span>
            </div>
            <div class="meta-row">
              <span>Synthetic Target:</span>
              <span>${scen.syntheticUser.user || 'Synthetic User'}</span>
            </div>
            <div class="meta-row">
              <span>Last Evaluated:</span>
              <span>${formatDate(scen.last_run_at)}</span>
            </div>
          </div>
        </div>
        <div style="display:flex; justify-content:space-between; align-items:center; margin-top:1rem; pt:1rem; border-top:1px solid var(--border-subtle);">
          <span style="font-size:0.75rem; color:var(--text-secondary);">Target: Enrolled Lab Endpoints</span>
          <button class="btn btn-primary" onclick="executeLabSimulation('${scen.id}')">
            <svg viewBox="0 0 24 24" fill="none" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
              <polygon points="5 3 19 12 5 21 5 3"></polygon>
            </svg>
            Run Isolated Simulation
          </button>
        </div>
      `;
      container.appendChild(card);
    });
  } catch (err) {
    console.error('Error loading lab scenarios:', err);
  }
}

window.executeLabSimulation = async function(scenarioId) {
  // Find first active lab device
  const labDevice = State.devices.find(d => d.is_lab_device);
  if (!labDevice) {
    showToast('No active lab device found to run simulation.', 'error');
    return;
  }

  showToast(`Dispatching simulation against ${labDevice.device_name}...`, 'info');

  try {
    const result = await API.runLabScenario(
      scenarioId,
      labDevice.id,
      State.currentUser.id,
      State.currentUser.role
    );

    renderLabSimulationOutput(result);
    showToast('Simulation complete. Browser and OS isolation verified.', 'success');
    loadLabScenarios();
  } catch (err) {
    showToast(`Simulation failed: ${err.message}`, 'error');
  }
};

function renderLabSimulationOutput(res) {
  const container = document.getElementById('lab-output-container');
  if (!container) return;
  container.style.display = 'block';

  document.getElementById('lab-exec-id').textContent = res.executionId;
  document.getElementById('lab-exec-device').textContent = `${res.targetLabDevice.name} (${res.targetLabDevice.platform})`;
  document.getElementById('lab-exec-scenario').textContent = res.scenarioName;
  document.getElementById('lab-exec-summary').textContent = res.summary;

  const evalList = document.getElementById('lab-evaluations-list');
  evalList.innerHTML = '';
  res.evaluations.forEach(ev => {
    const div = document.createElement('div');
    div.style.marginBottom = '0.75rem';
    div.style.padding = '0.5rem';
    div.style.background = 'rgba(255,255,255,0.02)';
    div.style.borderRadius = '4px';
    div.innerHTML = `
      <div style="display:flex; justify-content:space-between; margin-bottom:0.25rem;">
        <span style="color:#fff; font-weight:600;">${ev.boundary}</span>
        <span class="badge badge-secure">${ev.status} (${ev.result})</span>
      </div>
      <div style="font-size:0.75rem; color:#94a3b8;">${ev.test}</div>
      <div style="font-size:0.75rem; color:#6ee7b7; margin-top:0.25rem;">&bull; ${ev.detail}</div>
    `;
    evalList.appendChild(div);
  });

  container.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

// ====================================================================
// 6. TAMPER-EVIDENT AUDIT TRAIL CONTROLLER
// ====================================================================
async function loadAuditLogs() {
  try {
    const logs = await API.getAuditLogs(50);
    const tbody = document.getElementById('audit-logs-tbody');
    if (!tbody) return;

    tbody.innerHTML = '';
    logs.forEach(log => {
      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td><span class="code-inline" style="font-size:0.72rem;">${log.id}</span></td>
        <td><strong>${log.event_type}</strong></td>
        <td>${log.actor_id} [${log.actor_role}]</td>
        <td><span class="code-inline" style="font-size:0.72rem;">${log.action}</span></td>
        <td>
          <span class="code-inline" style="font-size:0.7rem; color:var(--accent-cyan); word-break:break-all;">
            ${log.tamper_hash.slice(0, 24)}...
          </span>
        </td>
        <td>${formatDate(log.created_at)}</td>
        <td>
          <button class="btn btn-outline" style="padding:0.2rem 0.5rem; font-size:0.72rem;" onclick="viewAuditDetailsModal('${log.id}')">
            Details
          </button>
        </td>
      `;
      tbody.appendChild(tr);
    });
  } catch (err) {
    console.error('Error loading audit logs:', err);
  }
}

window.viewAuditDetailsModal = async function(logId) {
  try {
    const logs = await API.getAuditLogs(100);
    const log = logs.find(l => l.id === logId);
    if (!log) return;

    document.getElementById('audit-detail-id').textContent = log.id;
    document.getElementById('audit-detail-event').textContent = log.event_type;
    document.getElementById('audit-detail-actor').textContent = `${log.actor_id} [${log.actor_role}]`;
    document.getElementById('audit-detail-hash').textContent = log.tamper_hash;
    document.getElementById('audit-detail-json').textContent = JSON.stringify(log.details, null, 2);

    openModal('modal-audit-detail');
  } catch (err) {
    showToast(`Error: ${err.message}`, 'error');
  }
};

async function handleVerifyAuditChain() {
  const btn = document.getElementById('btn-verify-chain');
  btn.disabled = true;
  btn.innerHTML = '<span class="pulse-dot"></span> Cryptographically Verifying...';

  try {
    const res = await API.verifyAuditChain();
    if (res.valid) {
      showToast(`Audit Chain INTEGRITY VERIFIED: All ${res.count} records pass SHA-256 blockchain verification.`, 'success');
      document.getElementById('audit-integrity-badge').className = 'badge badge-secure';
      document.getElementById('audit-integrity-badge').textContent = `VALID (${res.count} BLOCKS)`;
    } else {
      showToast(`INTEGRITY CORRUPTED at index ${res.corruptedIndex}! Expected: ${res.expectedHash.slice(0, 10)}...`, 'error');
      document.getElementById('audit-integrity-badge').className = 'badge badge-malicious';
      document.getElementById('audit-integrity-badge').textContent = 'TAMPER DETECTED';
    }
  } catch (err) {
    showToast(`Verification error: ${err.message}`, 'error');
  } finally {
    btn.disabled = false;
    btn.innerHTML = `
      <svg viewBox="0 0 24 24" fill="none" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path>
      </svg>
      Verify SHA-256 Chain Integrity
    `;
  }
}

window.openEnrollmentModal = function() {
  openModal('modal-enroll-device');
};
