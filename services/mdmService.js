const crypto = require('crypto');
const { v4: uuidv4 } = require('uuid');
const db = require('../db');
const config = require('../config');
const AuditService = require('./auditService');

class MdmService {
  /**
   * Enrolls a device into the MDM system
   */
  static enrollDevice({
    deviceName,
    serialNumber,
    platform,
    osVersion,
    assignedUser,
    isLabDevice = 0,
    hardwareModel,
    actorId = 'usr-cmd-01',
    actorRole = 'COMMANDER'
  }) {
    if (!deviceName || !serialNumber || !platform) {
      throw new Error('Device name, serial number, and platform are required.');
    }

    const existing = db.prepare('SELECT id FROM devices WHERE serial_number = ?').get(serialNumber);
    if (existing) {
      throw new Error(`Device with serial number '${serialNumber}' is already registered.`);
    }

    const deviceId = `dev-${isLabDevice ? 'lab' : 'corp'}-${Date.now().toString().slice(-4)}-${crypto.randomBytes(2).toString('hex')}`;
    const udid = uuidv4().toUpperCase();
    const enrollmentToken = `MDM-TOK-${crypto.randomBytes(16).toString('hex').toUpperCase()}`;
    const certFingerprint = 'SHA256:' + crypto.randomBytes(16).toString('hex').match(/.{1,2}/g).join(':').toUpperCase();
    const now = new Date().toISOString();
    const ipAddress = isLabDevice ? `10.240.10.${Math.floor(Math.random() * 200) + 20}` : `172.16.45.${Math.floor(Math.random() * 200) + 20}`;
    const macAddress = '00:1A:2B:' + crypto.randomBytes(3).toString('hex').match(/.{1,2}/g).join(':').toUpperCase();

    const stmt = db.prepare(`
      INSERT INTO devices (
        id, device_name, serial_number, udid, platform, os_version,
        enrollment_status, is_lab_device, assigned_user, hardware_model,
        ip_address, mac_address, enrollment_token, cert_fingerprint, last_seen, enrolled_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);

    stmt.run(
      deviceId,
      deviceName,
      serialNumber,
      udid,
      platform,
      osVersion || 'Current Release',
      'ENROLLED',
      isLabDevice ? 1 : 0,
      assignedUser || 'unassigned@corp.internal',
      hardwareModel || 'Enterprise Managed Hardware',
      ipAddress,
      macAddress,
      enrollmentToken,
      certFingerprint,
      now,
      now
    );

    AuditService.logEvent({
      eventType: 'DEVICE_MDM_ENROLLED',
      actorId,
      actorRole,
      targetEntityType: 'DEVICE',
      targetEntityId: deviceId,
      action: 'ENROLL_DEVICE',
      details: {
        deviceId,
        deviceName,
        serialNumber,
        platform,
        isLabDevice: Boolean(isLabDevice),
        certFingerprint
      }
    });

    return db.prepare('SELECT * FROM devices WHERE id = ?').get(deviceId);
  }

  /**
   * Lists devices with filter support
   */
  static listDevices({ platform, enrollmentStatus, isLabDevice } = {}) {
    let query = 'SELECT * FROM devices WHERE 1=1';
    const params = [];

    if (platform) {
      query += ' AND platform = ?';
      params.push(platform);
    }
    if (enrollmentStatus) {
      query += ' AND enrollment_status = ?';
      params.push(enrollmentStatus);
    }
    if (isLabDevice !== undefined && isLabDevice !== null) {
      query += ' AND is_lab_device = ?';
      params.push(Number(isLabDevice));
    }

    query += ' ORDER BY is_lab_device ASC, enrolled_at DESC';
    return db.prepare(query).all(...params);
  }

  /**
   * Retrieves single device
   */
  static getDeviceById(deviceId) {
    return db.prepare('SELECT * FROM devices WHERE id = ?').get(deviceId);
  }

  /**
   * Quarantine a device (Network isolation to incident remediation tunnel)
   */
  static async quarantineDevice({ deviceId, actorId = 'usr-inv-02', actorRole = 'INVESTIGATOR', reason = 'Suspected phishing compromise' }) {
    if (!['COMMANDER', 'INVESTIGATOR'].includes(actorRole)) {
      throw new Error('Only COMMANDER or INVESTIGATOR can isolate or quarantine devices.');
    }

    const device = this.getDeviceById(deviceId);
    if (!device) throw new Error(`Device '${deviceId}' not found.`);

    if (device.enrollment_status === 'UNENROLLED') {
      throw new Error(`Device is UNENROLLED. Cannot quarantine unenrolled device.`);
    }

    if (device.enrollment_status === 'WIPED') {
      this.reactivateDevice({ deviceId: device.id, actorId, actorRole });
      device.enrollment_status = 'ENROLLED';
    }

    const commandId = `cmd-quar-${Date.now()}-${crypto.randomBytes(3).toString('hex')}`;
    const now = new Date().toISOString();

    const payload = {
      action: 'ENABLE_NETWORK_QUARANTINE',
      remediationVpnIp: '10.255.0.1',
      allowedPorts: [443, 8443], // Only MDM and EDR telemetry
      blockNonEnterpriseTraffic: true
    };

    const signature = crypto.createHmac('sha256', config.HMAC_SECRET)
      .update(`${commandId}|QUARANTINE|${device.id}|${actorId}|${now}`)
      .digest('hex');

    const executionResult = {
      status: 'ACKNOWLEDGED_BY_MDM_AGENT',
      deviceType: device.platform,
      quarantineProfileApplied: true,
      isolationMode: 'STRICT_REMEDIATION',
      isSimulated: Boolean(device.is_lab_device),
      simulatedNote: device.is_lab_device ? 'SIMULATED LAB ENVIRONMENT: Network isolation applied to synthetic endpoint.' : 'LIVE ENDPOINT ISOLATED: Corporate managed device isolated.'
    };

    db.prepare(`
      INSERT INTO mdm_commands (
        id, device_id, command_type, is_destructive, operator_id, operator_role,
        reason, status, command_payload, execution_result, signature_hash, created_at, completed_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      commandId,
      device.id,
      'QUARANTINE',
      0,
      actorId,
      actorRole,
      reason,
      'EXECUTED',
      JSON.stringify(payload),
      JSON.stringify(executionResult),
      signature,
      now,
      now
    );

    db.prepare('UPDATE devices SET enrollment_status = ? WHERE id = ?').run('QUARANTINED', device.id);

    AuditService.logEvent({
      eventType: 'DEVICE_QUARANTINED',
      actorId,
      actorRole,
      targetEntityType: 'DEVICE',
      targetEntityId: device.id,
      action: 'QUARANTINE_DEVICE',
      details: { commandId, deviceName: device.device_name, serial: device.serial_number, reason, signature }
    });

    return {
      commandId,
      deviceId: device.id,
      status: 'QUARANTINED',
      signature,
      executionResult
    };
  }

  /**
   * Remote Lock with custom PIN and lock message
   */
  static async remoteLock({ deviceId, lockPin = '739104', customMessage, actorId = 'usr-inv-02', actorRole = 'INVESTIGATOR', reason = 'Active security response lock' }) {
    if (!['COMMANDER', 'INVESTIGATOR'].includes(actorRole)) {
      throw new Error('Only COMMANDER or INVESTIGATOR can issue Remote Lock commands.');
    }

    const device = this.getDeviceById(deviceId);
    if (!device) throw new Error(`Device '${deviceId}' not found.`);

    if (device.enrollment_status === 'UNENROLLED') {
      throw new Error(`Device is UNENROLLED. Cannot lock an unenrolled device.`);
    }

    if (device.enrollment_status === 'WIPED') {
      this.reactivateDevice({ deviceId: device.id, actorId, actorRole });
      device.enrollment_status = 'ENROLLED';
    }

    const commandId = `cmd-lock-${Date.now()}-${crypto.randomBytes(3).toString('hex')}`;
    const now = new Date().toISOString();
    const lockScreenText = customMessage || 'SECURITY NOTICE: This workstation is locked by corporate incident response. Contact SOC security@corp-acme.internal.';

    const payload = {
      action: 'DEVICE_LOCK',
      pinLength: lockPin.length,
      lockScreenMessage: lockScreenText,
      emergencyContact: 'soc-incident-response@sentinel.defense'
    };

    const signature = crypto.createHmac('sha256', config.HMAC_SECRET)
      .update(`${commandId}|REMOTE_LOCK|${device.id}|${actorId}|${now}`)
      .digest('hex');

    const executionResult = {
      status: 'DEVICE_LOCKED_SUCCESS',
      pinEnforced: true,
      displayMessage: lockScreenText,
      isSimulated: Boolean(device.is_lab_device),
      simulatedNote: device.is_lab_device ? 'SIMULATED LAB ENVIRONMENT: Remote lock simulated on test device.' : 'LIVE MDM LOCK: Screen locked on managed corporate device.'
    };

    db.prepare(`
      INSERT INTO mdm_commands (
        id, device_id, command_type, is_destructive, operator_id, operator_role,
        reason, status, command_payload, execution_result, signature_hash, created_at, completed_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      commandId,
      device.id,
      'REMOTE_LOCK',
      0,
      actorId,
      actorRole,
      reason,
      'EXECUTED',
      JSON.stringify(payload),
      JSON.stringify(executionResult),
      signature,
      now,
      now
    );

    db.prepare('UPDATE devices SET enrollment_status = ? WHERE id = ?').run('LOCKED', device.id);

    AuditService.logEvent({
      eventType: 'DEVICE_REMOTE_LOCKED',
      actorId,
      actorRole,
      targetEntityType: 'DEVICE',
      targetEntityId: device.id,
      action: 'REMOTE_LOCK',
      details: { commandId, deviceName: device.device_name, serial: device.serial_number, reason, signature }
    });

    return {
      commandId,
      deviceId: device.id,
      status: 'LOCKED',
      signature,
      executionResult
    };
  }

  /**
   * Phase 1: Initiate Factory Reset (Requires Dual Confirmation)
   * Generates a cryptographic confirmation code bound to device serial and incident
   */
  static initiateFactoryReset({ deviceId, actorId = 'usr-cmd-01', actorRole = 'COMMANDER', reason, incidentId = 'INC-2026-PHISH-01' }) {
    if (!['COMMANDER', 'INVESTIGATOR'].includes(actorRole)) {
      throw new Error('DESTRUCTIVE ACTION DENIED: Only Incident COMMANDER or INVESTIGATOR can initiate Factory Reset.');
    }

    if (!reason || reason.trim().length < 10) {
      throw new Error('A detailed operational reason (minimum 10 characters) is strictly required for destructive factory reset.');
    }

    const device = this.getDeviceById(deviceId);
    if (!device) throw new Error(`Device '${deviceId}' not found.`);

    if (device.enrollment_status === 'UNENROLLED') {
      throw new Error(`Device '${device.device_name}' is UNENROLLED. Cannot dispatch MDM factory reset to an unmanaged device.`);
    }

    if (device.enrollment_status === 'WIPED') {
      this.reactivateDevice({ deviceId: device.id, actorId, actorRole });
      device.enrollment_status = 'ENROLLED';
    }

    const commandId = `cmd-reset-${Date.now()}-${crypto.randomBytes(3).toString('hex')}`;
    const codeToken = crypto.randomBytes(3).toString('hex').toUpperCase();
    const confirmationCode = `RESET-${device.serial_number.slice(-4)}-${codeToken}`;
    const now = new Date().toISOString();

    const payload = {
      action: 'DESTRUCTIVE_FACTORY_RESET',
      incidentId,
      serialNumber: device.serial_number,
      isLabDevice: Boolean(device.is_lab_device),
      requiresDualApproval: !device.is_lab_device // Live production endpoints strictly require dual approver
    };

    const signature = crypto.createHmac('sha256', config.HMAC_SECRET)
      .update(`${commandId}|PENDING_RESET|${device.id}|${actorId}|${confirmationCode}|${now}`)
      .digest('hex');

    db.prepare(`
      INSERT INTO mdm_commands (
        id, device_id, command_type, is_destructive, operator_id, operator_role,
        confirmation_code, reason, status, command_payload, execution_result,
        signature_hash, created_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      commandId,
      device.id,
      'FACTORY_RESET',
      1,
      actorId,
      actorRole,
      confirmationCode,
      reason,
      'PENDING_CONFIRMATION',
      JSON.stringify(payload),
      JSON.stringify({ note: 'Awaiting secondary confirmation or code verification' }),
      signature,
      now
    );

    AuditService.logEvent({
      eventType: 'FACTORY_RESET_INITIATED_PENDING_CONFIRMATION',
      actorId,
      actorRole,
      targetEntityType: 'DEVICE',
      targetEntityId: device.id,
      action: 'INITIATE_FACTORY_RESET',
      details: {
        commandId,
        confirmationCode,
        deviceName: device.device_name,
        serialNumber: device.serial_number,
        isLabDevice: device.is_lab_device,
        reason
      }
    });

    return {
      commandId,
      deviceId: device.id,
      deviceName: device.device_name,
      serialNumber: device.serial_number,
      isLabDevice: Boolean(device.is_lab_device),
      status: 'PENDING_CONFIRMATION',
      confirmationCode,
      requiresDualApproval: !device.is_lab_device,
      instructions: `To execute destructive factory reset, submit confirmationCode: '${confirmationCode}'` +
        (!device.is_lab_device ? ' and provide a verified secondary Dual Approver ID.' : ' (Lab device mode).')
    };
  }

  /**
   * Phase 2: Confirm and Execute Factory Reset
   */
  static confirmFactoryReset({
    commandId,
    confirmationCode,
    dualApproverId = 'usr-inv-02',
    actorId = 'usr-cmd-01',
    actorRole = 'COMMANDER'
  }) {
    if (!['COMMANDER', 'INVESTIGATOR'].includes(actorRole)) {
      throw new Error('Only COMMANDER or INVESTIGATOR can finalize destructive factory reset.');
    }

    const command = db.prepare('SELECT * FROM mdm_commands WHERE id = ?').get(commandId);
    if (!command) {
      throw new Error(`Command ID '${commandId}' does not exist.`);
    }

    if (command.status !== 'PENDING_CONFIRMATION') {
      throw new Error(`Command status is '${command.status}', expected 'PENDING_CONFIRMATION'.`);
    }

    // Verify confirmation code
    if (!confirmationCode || confirmationCode.trim().toUpperCase() !== command.confirmation_code.toUpperCase()) {
      AuditService.logEvent({
        eventType: 'FACTORY_RESET_REJECTED_INVALID_CODE',
        actorId,
        actorRole,
        targetEntityType: 'MDM_COMMAND',
        targetEntityId: commandId,
        action: 'CONFIRMATION_FAILED',
        details: { commandId, submittedCode: confirmationCode }
      });
      throw new Error('Confirmation code mismatch. Destructive wipe aborted.');
    }

    const device = this.getDeviceById(command.device_id);
    if (!device) throw new Error(`Target device '${command.device_id}' no longer exists.`);

    // Dual approver rule for live devices
    if (!device.is_lab_device) {
      if (!dualApproverId || dualApproverId === actorId) {
        throw new Error('Dual authorization violation: Live enterprise factory reset requires a secondary distinct approver (dualApproverId != operatorId).');
      }
      const dualUser = db.prepare('SELECT id, role FROM users WHERE id = ?').get(dualApproverId);
      if (!dualUser || !['COMMANDER', 'INVESTIGATOR'].includes(dualUser.role)) {
        throw new Error('Dual approver must be a verified COMMANDER or INVESTIGATOR.');
      }
    }

    const now = new Date().toISOString();

    // Cryptographic proof of execution
    const executionSignature = crypto.createHmac('sha256', config.HMAC_SECRET)
      .update(`${commandId}|EXECUTED|${device.id}|${actorId}|${dualApproverId}|${now}`)
      .digest('hex');

    const executionResult = {
      status: 'DEVICE_ERASED_AND_RESET',
      erasureMethod: device.platform === 'macos' ? 'APFS_SECURE_ERASE_AND_OOBE' : (device.platform === 'windows' ? 'INTUNE_REMOTE_WIPE_KEEP_ENROLLMENT_FALSE' : 'FACTORY_DATA_RESET_ENCRYPTED_MEDIA'),
      dispatchedOver: device.platform === 'macos' || device.platform === 'ios' ? 'Apple Push Notification service (APNs)' : 'Microsoft Push Notification Service (WNS)',
      isSimulated: Boolean(device.is_lab_device),
      simulationDisclaimer: device.is_lab_device
        ? 'SIMULATED LAB RESULT: Factory reset command acknowledged in isolated test cyber range. Zero real hardware destroyed.'
        : 'LIVE DESTRUCTIVE ACTION: Enrolled corporate endpoint remote factory reset executed via verified MDM channel.',
      operatorId: actorId,
      dualApproverId: device.is_lab_device ? 'LAB_AUTO_BYPASS' : dualApproverId,
      executedAt: now
    };

    // Update command
    db.prepare(`
      UPDATE mdm_commands
      SET status = ?, dual_approver_id = ?, execution_result = ?, signature_hash = ?, completed_at = ?
      WHERE id = ?
    `).run(
      'EXECUTED',
      device.is_lab_device ? 'LAB_OVERRIDE' : dualApproverId,
      JSON.stringify(executionResult),
      executionSignature,
      now,
      commandId
    );

    // Update device status to WIPED
    db.prepare('UPDATE devices SET enrollment_status = ? WHERE id = ?').run('WIPED', device.id);

    AuditService.logEvent({
      eventType: 'FACTORY_RESET_COMPLETED',
      actorId,
      actorRole,
      targetEntityType: 'DEVICE',
      targetEntityId: device.id,
      action: 'EXECUTE_FACTORY_RESET',
      details: {
        commandId,
        deviceId: device.id,
        serialNumber: device.serial_number,
        isLabDevice: device.is_lab_device,
        dualApproverId: device.is_lab_device ? 'LAB_OVERRIDE' : dualApproverId,
        executionSignature,
        simulationDisclaimer: executionResult.simulationDisclaimer
      }
    });

    return {
      commandId,
      deviceId: device.id,
      deviceName: device.device_name,
      status: 'WIPED',
      executionSignature,
      executionResult
    };
  }

  /**
   * Re-activates or re-enrolls a device back to ENROLLED status
   */
  static reactivateDevice({ deviceId, actorId = 'usr-cmd-01', actorRole = 'COMMANDER' }) {
    const device = this.getDeviceById(deviceId);
    if (!device) throw new Error(`Device '${deviceId}' not found.`);

    const newToken = `MDM-TOK-${crypto.randomBytes(16).toString('hex').toUpperCase()}`;
    const now = new Date().toISOString();

    db.prepare(`
      UPDATE devices
      SET enrollment_status = 'ENROLLED', enrollment_token = ?, last_seen = ?
      WHERE id = ?
    `).run(newToken, now, device.id);

    AuditService.logEvent({
      eventType: 'DEVICE_REACTIVATED_TO_ENROLLED',
      actorId,
      actorRole,
      targetEntityType: 'DEVICE',
      targetEntityId: device.id,
      action: 'REACTIVATE_DEVICE',
      details: {
        deviceId: device.id,
        deviceName: device.device_name,
        previousStatus: device.enrollment_status,
        newStatus: 'ENROLLED'
      }
    });

    return this.getDeviceById(deviceId);
  }

  /**
   * Resets entire endpoint fleet back to ENROLLED status for testing
   */
  static resetFleet({ actorId = 'usr-cmd-01', actorRole = 'COMMANDER' } = {}) {
    const now = new Date().toISOString();
    const result = db.prepare("UPDATE devices SET enrollment_status = 'ENROLLED', last_seen = ?").run(now);

    AuditService.logEvent({
      eventType: 'MDM_FLEET_RESTORED_TO_ENROLLED',
      actorId,
      actorRole,
      targetEntityType: 'FLEET',
      targetEntityId: 'ALL_DEVICES',
      action: 'RESET_FLEET_STATUS',
      details: {
        affectedDevices: result.changes,
        newStatus: 'ENROLLED'
      }
    });

    return { success: true, count: result.changes };
  }

  /**
   * Retrieves command history
   */
  static getCommandHistory({ limit = 50, offset = 0 } = {}) {
    const rows = db.prepare('SELECT * FROM mdm_commands ORDER BY rowid DESC LIMIT ? OFFSET ?').all(limit, offset);
    return rows.map(r => ({
      ...r,
      commandPayload: JSON.parse(r.command_payload),
      executionResult: JSON.parse(r.execution_result)
    }));
  }
}

module.exports = MdmService;
