const crypto = require('crypto');
const db = require('../db');

class AuditService {
  /**
   * Appends an audit event to the tamper-evident log chain
   */
  static logEvent({
    eventType,
    actorId = 'SYSTEM',
    actorRole = 'SYSTEM',
    targetEntityType = 'UNKNOWN',
    targetEntityId = 'UNKNOWN',
    action,
    details = {},
    ipAddress = '127.0.0.1'
  }) {
    const id = `audit-${Date.now()}-${crypto.randomBytes(4).toString('hex')}`;
    const createdAt = new Date().toISOString();

    // Get previous tamper_hash to create an immutable cryptographic chain
    const lastRow = db.prepare('SELECT tamper_hash FROM audit_logs ORDER BY rowid DESC LIMIT 1').get();
    const prevHash = lastRow ? lastRow.tamper_hash : '0000000000000000000000000000000000000000000000000000000000000000';

    const detailsStr = typeof details === 'string' ? details : JSON.stringify(details);

    // Compute tamper-evident hash chaining to previous entry
    const hashPayload = `${prevHash}|${id}|${eventType}|${actorId}|${actorRole}|${action}|${targetEntityType}|${targetEntityId}|${detailsStr}|${createdAt}`;
    const tamperHash = crypto.createHash('sha256').update(hashPayload).digest('hex');

    const stmt = db.prepare(`
      INSERT INTO audit_logs (
        id, event_type, actor_id, actor_role, target_entity_type, target_entity_id,
        action, details, ip_address, tamper_hash, created_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);

    stmt.run(
      id,
      eventType,
      actorId,
      actorRole,
      targetEntityType,
      targetEntityId,
      action,
      detailsStr,
      ipAddress,
      tamperHash,
      createdAt
    );

    return {
      id,
      tamperHash,
      createdAt
    };
  }

  /**
   * Retrieves audit logs with optional filtering
   */
  static getLogs({ limit = 100, offset = 0, eventType = null } = {}) {
    let query = 'SELECT * FROM audit_logs';
    const params = [];

    if (eventType) {
      query += ' WHERE event_type = ?';
      params.push(eventType);
    }

    query += ' ORDER BY rowid DESC LIMIT ? OFFSET ?';
    params.push(limit, offset);

    const rows = db.prepare(query).all(...params);
    return rows.map(r => ({
      ...r,
      details: (() => {
        try {
          return JSON.parse(r.details);
        } catch {
          return r.details;
        }
      })()
    }));
  }

  /**
   * Verifies the cryptographic chain integrity of the audit log
   */
  static verifyChainIntegrity() {
    const rows = db.prepare('SELECT * FROM audit_logs ORDER BY rowid ASC').all();
    if (rows.length === 0) return { valid: true, count: 0, corruptedIndex: null };

    let prevHash = '0000000000000000000000000000000000000000000000000000000000000000';

    for (let i = 0; i < rows.length; i++) {
      const row = rows[i];
      if (i === 0 && row.id === 'audit-genesis-00') {
        // Genesis block recorded during initial seed
        prevHash = row.tamper_hash;
        continue;
      }

      const hashPayload = `${prevHash}|${row.id}|${row.event_type}|${row.actor_id}|${row.actor_role}|${row.action}|${row.target_entity_type}|${row.target_entity_id}|${row.details}|${row.created_at}`;
      const expectedHash = crypto.createHash('sha256').update(hashPayload).digest('hex');

      if (expectedHash !== row.tamper_hash) {
        return {
          valid: false,
          count: rows.length,
          corruptedIndex: i,
          corruptedLogId: row.id,
          expectedHash,
          actualHash: row.tamper_hash
        };
      }
      prevHash = row.tamper_hash;
    }

    return {
      valid: true,
      count: rows.length,
      latestHash: prevHash
    };
  }
}

module.exports = AuditService;
