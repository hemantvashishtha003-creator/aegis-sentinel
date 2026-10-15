let app;
try {
  app = require('../server');
} catch (err) {
  console.error('[VERCEL-BOOT-ERROR]', err);
  const express = require('express');
  app = express();
  app.all('*', (req, res) => {
    res.status(500).json({
      error: 'Vercel Serverless Boot Failure',
      message: err.message,
      stack: err.stack
    });
  });
}

module.exports = app;
