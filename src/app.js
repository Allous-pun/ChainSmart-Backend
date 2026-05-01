const express = require('express');
const cors = require('cors');
require('dotenv').config();

// Import module routes
const authRoutes = require('./modules/auth/routes');
const organizationRoutes = require('./modules/organization/routes');
const userRoutes = require('./modules/users/routes');
const settingsRoutes = require('./modules/settings/routes');
const organizationSettingsRoutes = require('./modules/organizationSettings/routes');
const rolesRoutes = require('./modules/roles/routes');

// Import middleware
const { authenticate, requireOrgCode } = require('./middleware/auth');

const app = express();

app.use(cors());
app.use(express.json());

// Public routes (no auth needed)
app.use('/api/auth', authRoutes);
app.use('/api/organization', organizationRoutes);
app.use('/api/users/owner', userRoutes);

// Protected routes (require authentication)
app.use('/api/users', authenticate, userRoutes);
app.use('/api/roles', authenticate, rolesRoutes);
app.use('/api/settings', authenticate, requireOrgCode, settingsRoutes);
app.use('/api/organization-settings', authenticate, requireOrgCode, organizationSettingsRoutes);

app.get('/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

app.get('/', (req, res) => {
  res.json({ message: 'ChainSmart API Running', version: '1.0.0' });
});

module.exports = app;