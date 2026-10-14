const express = require('express');
const cors = require('cors');
const path = require('path');
const config = require('./config');

// Initialize database
require('./db');

const assessmentRoutes = require('./routes/assessmentRoutes');
const evidenceRoutes = require('./routes/evidenceRoutes');
const mdmRoutes = require('./routes/mdmRoutes');
const labRoutes = require('./routes/labRoutes');
const auditRoutes = require('./routes/auditRoutes');
const userRoutes = require('./routes/userRoutes');

const app = express();

app.use(cors());
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));

// Resolve frontend static assets directory
const fs = require('fs');
const publicDir = fs.existsSync(path.join(__dirname, 'public'))
  ? path.join(__dirname, 'public')
  : path.join(process.cwd(), 'public');

app.use(express.static(publicDir));

// Mount API routes
app.use('/api/assessment', assessmentRoutes);
app.use('/api/evidence', evidenceRoutes);
app.use('/api/mdm', mdmRoutes);
app.use('/api/lab', labRoutes);
app.use('/api/audit', auditRoutes);
app.use('/api/users', userRoutes);
app.use('/api/stats', userRoutes); // Mount stats routes

// Fallback to index.html for SPA navigation
app.use((req, res) => {
  res.sendFile(path.join(publicDir, 'index.html'));
});

// Global error handler
app.use((err, req, res, next) => {
  console.error('[AEGIS-ERROR]', err);
  res.status(500).json({
    success: false,
    error: err.message || 'Internal Server Error'
  });
});

if (require.main === module) {
  app.listen(config.PORT, config.HOST, () => {
    console.log(`\n======================================================`);
    console.log(`🛡️  AEGIS-SENTINEL: Device Security & Incident Response`);
    console.log(`⚡ Server running at http://${config.HOST}:${config.PORT}`);
    console.log(`🔒 Vault Cipher: AES-256-GCM | Audit MAC: HMAC-SHA256`);
    console.log(`======================================================\n`);
  });
}

module.exports = app;
