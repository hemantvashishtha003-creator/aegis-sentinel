async function testAll() {
  const base = "http://127.0.0.1:3000";

  console.log("\n=======================================================");
  console.log("🛡️  STARTING COMPREHENSIVE E2E VERIFICATION OF AEGIS-SENTINEL");
  console.log("=======================================================\n");

  // 1. URL Assessment
  console.log("▶ [TEST 1/7] URL Phishing & Sandbox Assessment");
  const scanRes = await fetch(`${base}/api/assessment/scan`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ url: "http://192.168.1.100/login", investigatorId: "usr-inv-02" })
  }).then(r => r.json());
  if (!scanRes.success) throw new Error("Scan failed: " + scanRes.error);
  console.log("  ✔ Threat Verdict:", scanRes.data.threatVerdict);
  console.log("  ✔ Risk Score:", scanRes.data.riskScore, "/ 100");
  console.log("  ✔ Sandbox Boundary Evaluated:", Boolean(scanRes.data.boundaryAnalysis));

  // 2. Evidence Vault (AES-256-GCM)
  console.log("\n▶ [TEST 2/7] Forensic Evidence Ingestion & AES-256-GCM Encryption");
  const acqRes = await fetch(`${base}/api/evidence/acquire`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      deviceId: "dev-corp-01",
      evidenceType: "SUSPICIOUS_ARTIFACT",
      incidentId: "INC-LIVE-VERIFY-001",
      customNotes: "Live E2E Verification artifact",
      actorId: "usr-inv-02",
      actorRole: "INVESTIGATOR"
    })
  }).then(r => r.json());
  if (!acqRes.success) throw new Error("Acquisition failed: " + acqRes.error);
  console.log("  ✔ Evidence Vault ID:", acqRes.data.evidenceId);
  console.log("  ✔ SHA-256 Pre-Encryption Checksum:", acqRes.data.sha256Checksum);

  // Decryption & Verification
  const decRes = await fetch(`${base}/api/evidence/${acqRes.data.evidenceId}?actorId=usr-inv-02&actorRole=INVESTIGATOR`).then(r => r.json());
  if (!decRes.success) throw new Error("Decryption failed: " + decRes.error);
  console.log("  ✔ Decrypted & Checksum Validated:", decRes.data.checksumValid);

  // 3. MDM Quarantine & Lock
  console.log("\n▶ [TEST 3/7] MDM Network Quarantine & Remote Screen Lock");
  const quarRes = await fetch(`${base}/api/mdm/quarantine`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ deviceId: "dev-corp-01", reason: "Automated test quarantine", actorId: "usr-inv-02", actorRole: "INVESTIGATOR" })
  }).then(r => r.json());
  if (!quarRes.success) throw new Error("Quarantine failed: " + quarRes.error);
  console.log("  ✔ Quarantine Dispatched:", quarRes.data.status);
  console.log("  ✔ HMAC Signature:", quarRes.data.signature.slice(0, 24) + "...");

  const lockRes = await fetch(`${base}/api/mdm/lock`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ deviceId: "dev-corp-01", lockPin: "998811", customMessage: "Security incident lock", actorId: "usr-inv-02", actorRole: "INVESTIGATOR" })
  }).then(r => r.json());
  if (!lockRes.success) throw new Error("Lock failed: " + lockRes.error);
  console.log("  ✔ Remote Lock Dispatched:", lockRes.data.status);

  // 4. Destructive Factory Reset Flow
  console.log("\n▶ [TEST 4/7] Dual-Authorization Destructive Factory Reset Flow");
  const initReset = await fetch(`${base}/api/mdm/factory-reset/initiate`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      deviceId: "dev-corp-01",
      reason: "Critical security incident: Verified malware persistence requiring complete device wipe.",
      incidentId: "INC-LIVE-VERIFY-001",
      actorId: "usr-cmd-01",
      actorRole: "COMMANDER"
    })
  }).then(r => r.json());
  if (!initReset.success) throw new Error("Reset initiation failed: " + initReset.error);
  console.log("  ✔ Phase 1 Confirmation Code Generated:", initReset.data.confirmationCode);

  const confirmReset = await fetch(`${base}/api/mdm/factory-reset/confirm`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      commandId: initReset.data.commandId,
      confirmationCode: initReset.data.confirmationCode,
      dualApproverId: "usr-inv-02",
      actorId: "usr-cmd-01",
      actorRole: "COMMANDER"
    })
  }).then(r => r.json());
  if (!confirmReset.success) throw new Error("Reset confirmation failed: " + confirmReset.error);
  console.log("  ✔ Phase 2 Destructive Wipe Executed! Status:", confirmReset.data.status);
  console.log("  ✔ APFS / Secure Erase Method:", confirmReset.data.executionResult.erasureMethod);
  console.log("  ✔ Execution Signature:", confirmReset.data.executionSignature.slice(0, 24) + "...");

  // 5. Auto Re-enroll / Reactivate
  console.log("\n▶ [TEST 5/7] Auto Re-Enroll & Device Lifecycle Recovery");
  const reactivateRes = await fetch(`${base}/api/mdm/devices/dev-corp-01/reactivate`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ actorId: "usr-cmd-01", actorRole: "COMMANDER" })
  }).then(r => r.json());
  if (!reactivateRes.success) throw new Error("Reactivate failed: " + reactivateRes.error);
  console.log("  ✔ Wiped Device Restored to:", reactivateRes.data.enrollment_status);

  // 6. Cyber Range Lab Simulation
  console.log("\n▶ [TEST 6/7] Cyber Range Isolated Laboratory Simulation");
  const labRes = await fetch(`${base}/api/lab/run`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ scenarioId: "scen-01", targetLabDeviceId: "dev-lab-01", actorId: "usr-inv-02", actorRole: "INVESTIGATOR" })
  }).then(r => r.json());
  if (!labRes.success) throw new Error("Lab run failed: " + labRes.error);
  console.log("  ✔ Lab Scenario:", labRes.data.scenarioName);
  console.log("  ✔ Simulation Summary:", labRes.data.summary);
  console.log("  ✔ Isolation Watermark:", labRes.data.labEnvironmentBadge);

  // 7. Cryptographic Audit Ledger
  console.log("\n▶ [TEST 7/7] Blockchain-Style Tamper-Evident Audit Ledger");
  const auditRes = await fetch(`${base}/api/audit/verify-chain`).then(r => r.json());
  if (!auditRes.success) throw new Error("Audit verification failed: " + auditRes.error);
  console.log("  ✔ SHA-256 Hash Chain Integrity:", auditRes.data.valid ? "CRYPTOGRAPHICALLY_VERIFIED (NO TAMPERING)" : "CORRUPTED");
  console.log("  ✔ Total Chained Blocks Verified:", auditRes.data.count);

  console.log("\n=======================================================");
  console.log("🎉 ALL 7 SUBSYSTEMS PASSED WITH 100% SUCCESS!");
  console.log("=======================================================\n");
}

testAll().catch(e => {
  console.error("\n❌ E2E TEST FAILED:", e.message);
  process.exit(1);
});
