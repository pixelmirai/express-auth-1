const { PrismaClient } = require('@prisma/client');
const config = require('../../config/env');
const logger = require('../../utils/logger');

const prisma = new PrismaClient({
  datasources: {
    db: {
      url: config.database.url,
    },
  },
  log: config.env === 'development'
      ? ['query', 'info', 'warn', 'error']
      : ['warn', 'error'],
});

// Removed the beforeExit hook — Prisma 5 library engine no longer supports this.

module.exports = prisma;
