const app = require('./app');
const config = require('./config/env');
const logger = require('./utils/logger');

let isShuttingDown = false;

const server = app.listen(config.app.port, () => {
  logger.info(`Server listening on port ${config.app.port}`);
});

const shutdown = (signal) => {
  if (isShuttingDown) return;
  isShuttingDown = true;
  logger.info({ signal }, 'Shutting down server');
  server.close(() => {
    process.exit(0);
  });
};

process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);
process.on('uncaughtException', (error) => {
  logger.error({ err: error }, 'Uncaught exception');
  shutdown('uncaughtException');
});
process.on('unhandledRejection', (reason) => {
  logger.error({ err: reason }, 'Unhandled promise rejection');
  shutdown('unhandledRejection');
});

module.exports = server;
