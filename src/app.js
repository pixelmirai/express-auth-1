// app.js
const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const morgan = require('morgan');
const rateLimit = require('express-rate-limit');
const cookieParser = require('cookie-parser');

const config = require('./config/env');
const logger = require('./utils/logger');
const errorHandler = require('./middleware/errorHandler');

const authRoutes = require('./modules/auth/auth.routes');
const userRoutes = require('./modules/users/users.routes');
const adminRoutes = require('./modules/admin/admin.routes');

const app = express();

// behind proxies (PaaS/CDN) so cookies and IPs behave
app.set('trust proxy', 1);

// Security headers
app.use(
    helmet({
      // Keep defaults; allow JSON and fetch, don't break OAuth redirects
      crossOriginResourcePolicy: { policy: 'cross-origin' },
    })
);

// CORS: allow your app origin and credentials for cookie refresh
// In dev, using { origin: true } is fine; in prod, restrict to APP_URL
// CORS: allow prod app URL + common localhost dev origins
const allowedOrigins = [
    config.app.url,                 // your deployed frontend (prod)
    'http://localhost:3000', 
      'http://localhost:3001',        // CRA/Next dev
    'http://127.0.0.1:3000',
    'http://localhost:5173',        // Vite
    'http://127.0.0.1:5173',
];

const corsOptions = (req, cb) => {
    const origin = req.header('Origin');
    const allow = !origin || allowedOrigins.includes(origin); // allow non-browser clients too
    cb(null, {
        origin: allow,
        credentials: true,
    });
};

app.use(cors(corsOptions));
app.options('*', cors(corsOptions));

// Body + cookies
app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());

// Global rate limit (coarse). Fine-grained per-route limits will live in auth module.
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  standardHeaders: true,
  legacyHeaders: false,
});
app.use(limiter);

// Logging
app.use(
    morgan(config.env === 'production' ? 'combined' : 'dev', {
      stream: {
        write: (message) => logger.info(message.trim()),
      },
    })
);

// Health
app.get('/health', (req, res) => {
  res.json({ status: 'ok', uptime: process.uptime() });
});

// Routes
app.use('/auth', authRoutes);
app.use('/users', userRoutes);
app.use('/admin', adminRoutes);

// 404
app.use((req, res) => {
  res.status(404).json({ status: 'error', message: 'Not found' });
});

// Centralized error handler
app.use(errorHandler);

module.exports = app;
