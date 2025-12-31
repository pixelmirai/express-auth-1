const express = require('express');
const controller = require('./users.controller');
const authMiddleware = require('../../middleware/authMiddleware');

const router = express.Router();

router.get('/me', authMiddleware, controller.getMe);

module.exports = router;
