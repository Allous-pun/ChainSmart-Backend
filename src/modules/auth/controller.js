const bcrypt = require('bcrypt');
const User = require('../users/model');
const { generateToken, createSession, findUserByPin, logout: logoutSession, logoutAllDevices, getActiveSessions } = require('./service');

const login = async (req, res) => {
  try {
    const { pin } = req.body;
    const deviceId = req.headers['x-device-id'] || null;
    const ipAddress = req.ip || req.connection.remoteAddress;
    const userAgent = req.headers['user-agent'];
    const orgCode = req.headers['x-orgcode'];
    
    if (!pin) {
      return res.status(400).json({ success: false, error: 'PIN is required' });
    }
    
    if (!orgCode) {
      return res.status(400).json({ success: false, error: 'x-orgcode header is required' });
    }
    
    const user = await findUserByPin(orgCode, pin);
    
    if (!user) {
      return res.status(401).json({ success: false, error: 'Invalid PIN' });
    }
    
    const token = generateToken(user, user.branchId);
    
    await createSession(
      user._id,
      user.orgCode,
      user.branchId,
      token,
      deviceId,
      ipAddress,
      userAgent
    );
    
    user.lastLoginAt = new Date();
    user.lastLoginIP = ipAddress;
    await user.save();
    
    res.json({
      success: true,
      data: {
        token,
        user: {
          id: user._id,
          name: user.name,
          role: user.role,
          orgCode: user.orgCode,
          branchId: user.branchId,
          canSwitchBranches: user.role === 'owner'
        }
      },
      message: 'Login successful'
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ success: false, error: error.message });
  }
};

const logout = async (req, res) => {
  try {
    await logoutSession(req.token);  // Changed from logout to logoutSession
    res.json({ success: true, message: 'Logged out successfully' });
  } catch (error) {
    console.error('Logout error:', error);
    res.status(500).json({ success: false, error: error.message });
  }
};

const logoutAll = async (req, res) => {
  try {
    await logoutAllDevices(req.user.id);
    res.json({ success: true, message: 'Logged out from all devices' });
  } catch (error) {
    console.error('Logout all error:', error);
    res.status(500).json({ success: false, error: error.message });
  }
};

const getSessions = async (req, res) => {
  try {
    const sessions = await getActiveSessions(req.user.id);
    res.json({ success: true, data: sessions });
  } catch (error) {
    console.error('Get sessions error:', error);
    res.status(500).json({ success: false, error: error.message });
  }
};

const verify = async (req, res) => {
  try {
    res.json({ 
      success: true, 
      data: { 
        user: req.user,
        tokenValid: true 
      } 
    });
  } catch (error) {
    res.status(401).json({ success: false, error: 'Invalid token' });
  }
};

const changePin = async (req, res) => {
  try {
    const { oldPin, newPin } = req.body;
    const userId = req.user.id;
    
    if (!oldPin || !newPin) {
      return res.status(400).json({ success: false, error: 'Old PIN and new PIN are required' });
    }
    
    if (!/^\d{8}$/.test(newPin)) {
      return res.status(400).json({ success: false, error: 'New PIN must be exactly 8 digits' });
    }
    
    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ success: false, error: 'User not found' });
    }
    
    const isValid = await bcrypt.compare(oldPin, user.pin);
    if (!isValid) {
      return res.status(401).json({ success: false, error: 'Old PIN is incorrect' });
    }
    
    const hashedPin = await bcrypt.hash(newPin, 10);
    user.pin = hashedPin;
    await user.save();
    
    await logoutAllDevices(userId);
    
    res.json({ success: true, message: 'PIN changed successfully. Please login again.' });
  } catch (error) {
    console.error('Change PIN error:', error);
    res.status(500).json({ success: false, error: error.message });
  }
};

module.exports = {
  login,
  logout,
  logoutAll,
  getSessions,
  verify,
  changePin
};