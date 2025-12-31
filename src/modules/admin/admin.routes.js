const express = require('express');
const controller = require('./admin.controller');
const authMiddleware = require('../../middleware/authMiddleware');
const roleMiddleware = require('../../middleware/roleMiddleware');

const router = express.Router();

router.use(authMiddleware, roleMiddleware(['admin']));

router.get('/users', controller.listUsers);
router.get('/users/:id', controller.getUserById);
router.patch('/users/:id/ban', controller.banUser);
router.patch('/users/:id/unban', controller.unbanUser);
router.delete('/users/:id/delete', controller.deleteUser);

module.exports = router;
