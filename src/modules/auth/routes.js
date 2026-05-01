const express = require('express');
const router = express.Router();
const authController = require('./controller');
const { authenticate } = require('../../middleware/auth');

// Public routes
router.post('/login', authController.login);

// Protected routes
router.post('/logout', authenticate, authController.logout);
router.post('/logout-all', authenticate, authController.logoutAll);
router.get('/sessions', authenticate, authController.getSessions);
router.get('/verify', authenticate, authController.verify);
router.post('/change-pin', authenticate, authController.changePin);

module.exports = router;