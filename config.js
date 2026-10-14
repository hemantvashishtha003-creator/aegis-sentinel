const path = require('path');

const isVercel = Boolean(process.env.VERCEL || process.env.AWS_LAMBDA_FUNCTION_NAME);
const defaultDbPath = isVercel
  ? path.join('/tmp', 'security_sentinel.sqlite')
  : path.join(__dirname, 'security_sentinel.sqlite');

module.exports = {
  PORT: process.env.PORT || 3000,
  HOST: process.env.HOST || '0.0.0.0',
  DB_PATH: process.env.DB_PATH || defaultDbPath,
  // Cryptographic Master Key for Evidence Vault (AES-256-GCM)
  // In production, this would be retrieved from Hardware Security Module (HSM) / Key Vault
  MASTER_ENCRYPTION_KEY: process.env.MASTER_ENCRYPTION_KEY || 'ae92f38d17b4c6e9821a4f5c9e2b8d7a1f4c6e8b2a3d5f7e9c1b3a5d7e9f1a3c',
  HMAC_SECRET: process.env.HMAC_SECRET || 'sentinel-mdm-tamper-proof-hmac-secret-key-2026',
  DEFAULT_RETENTION_DAYS: 90,
  ALLOW_SIMULATED_DESTRUCTIVE: true // Allows full factory reset execution on LAB devices; live devices strictly enforce dual auth
};
