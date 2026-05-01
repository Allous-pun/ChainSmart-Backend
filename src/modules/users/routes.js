const express = require('express');
const router = express.Router();
const userController = require('./controller');
const { authenticate, requirePermission } = require('../../middleware/auth');

// Public route (no auth needed for creating owner after org creation)
router.post('/owner', userController.createOwner);

// Protected routes (require authentication)
router.post('/employee', authenticate, requirePermission('create_user'), userController.createEmployee);
router.get('/', authenticate, requirePermission('view_users'), userController.getUsers);
router.get('/:userId', authenticate, requirePermission('view_users'), userController.getUser);
router.put('/:userId', authenticate, requirePermission('edit_user'), userController.updateUser);
router.delete('/:userId', authenticate, requirePermission('delete_user'), userController.deleteUser);

module.exports = router;