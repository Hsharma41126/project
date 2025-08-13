const express = require('express');
const jwt = require('jsonwebtoken');
const { body, validationResult } = require('express-validator');
const User = require('../models/User');
const { auth } = require('../middleware/auth');

const router = express.Router();

// Register
router.post('/register', [
  body('name').trim().isLength({ min: 2 }).withMessage('Name must be at least 2 characters'),
  body('username').trim().isLength({ min: 3 }).withMessage('Username must be at least 3 characters'),
  body('email').isEmail().withMessage('Please provide a valid email'),
  body('password').isLength({ min: 3 }).withMessage('Password must be at least 3 characters'),
  body('phone').trim().notEmpty().withMessage('Phone number is required'),
  body('role').optional().isIn(['Admin', 'Staff', 'Manager', 'User']).withMessage('Invalid role')
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        success: false,
        message: 'Validation failed',
        errors: errors.array()
      });
    }

    const { name, username, email, password, phone, role = 'User' } = req.body;

    // Check if user already exists
    const existingUser = await User.findOne({
      where: {
        $or: [{ email }, { username }]
      }
    });

    if (existingUser) {
      return res.status(400).json({
        success: false,
        message: 'User with this email or username already exists'
      });
    }

    // Set default permissions based on role
    let permissions = {};
    if (role === 'Admin') {
      permissions = {
        tablesManagement: { view: true, manage: true, status: true },
        orderProcessing: { create: true, modify: true, cancel: true },
        billingAccess: { generate: true, payments: true, reports: true },
        kotManagement: { print: true, modify: true, status: true },
        specialPermissions: {
          voidOrders: { items: true, fullOrder: true, afterPayment: true },
          discounts: { item: true, bill: true, offers: true, maxDiscount: 25 }
        },
        reportAccess: { daily: true, table: true, item: true },
        canAddItems: true,
        canChangePrices: true,
        canManageStaff: true
      };
    } else if (role === 'Manager') {
      permissions = {
        tablesManagement: { view: true, manage: true, status: true },
        orderProcessing: { create: true, modify: true, cancel: true },
        billingAccess: { generate: true, payments: true, reports: true },
        kotManagement: { print: true, modify: true, status: true },
        specialPermissions: {
          voidOrders: { items: true, fullOrder: false, afterPayment: false },
          discounts: { item: true, bill: true, offers: true, maxDiscount: 15 }
        },
        reportAccess: { daily: true, table: true, item: true },
        canAddItems: true,
        canChangePrices: true,
        canManageStaff: false
      };
    } else if (role === 'Staff') {
      permissions = {
        tablesManagement: { view: true, manage: false, status: true },
        orderProcessing: { create: true, modify: false, cancel: false },
        billingAccess: { generate: false, payments: false, reports: false },
        kotManagement: { print: true, modify: false, status: true },
        specialPermissions: {
          voidOrders: { items: false, fullOrder: false, afterPayment: false },
          discounts: { item: false, bill: false, offers: false, maxDiscount: 0 }
        },
        reportAccess: { daily: false, table: false, item: false },
        canAddItems: false,
        canChangePrices: false,
        canManageStaff: false
      };
    }

    // Create user
    const user = await User.create({
      name,
      username,
      email,
      password,
      phone,
      role,
      permissions
    });

    // Generate JWT token
    const token = jwt.sign(
      { id: user.id, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: process.env.JWT_EXPIRE || '7d' }
    );

    res.status(201).json({
      success: true,
      message: 'User registered successfully',
      data: {
        user: {
          id: user.id,
          name: user.name,
          username: user.username,
          email: user.email,
          phone: user.phone,
          role: user.role
        },
        token
      }
    });
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error during registration'
    });
  }
});

// Login
router.post('/login', [
  body('email').isEmail().withMessage('Please provide a valid email'),
  body('password').notEmpty().withMessage('Password is required'),
  body('role').notEmpty().withMessage('Role is required')
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        success: false,
        message: 'Validation failed',
        errors: errors.array()
      });
    }

    const { email, password, role } = req.body;

    // Find user by email and role
    const user = await User.findOne({
      where: { email, role, is_active: true }
    });

    if (!user) {
      return res.status(401).json({
        success: false,
        message: 'Invalid credentials or role'
      });
    }

    // Check password
    const isMatch = await user.comparePassword(password);
    if (!isMatch) {
      return res.status(401).json({
        success: false,
        message: 'Invalid credentials'
      });
    }

    // Update last login
    await user.update({ last_login: new Date() });

    // Generate JWT token
    const token = jwt.sign(
      { id: user.id, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: process.env.JWT_EXPIRE || '7d' }
    );

    res.json({
      success: true,
      message: 'Login successful',
      data: {
        user: {
          id: user.id,
          name: user.name,
          username: user.username,
          email: user.email,
          phone: user.phone,
          role: user.role,
          permissions: user.permissions
        },
        token
      }
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error during login'
    });
  }
});

// Get current user
router.get('/me', auth, async (req, res) => {
  try {
    const user = await User.findByPk(req.user.id, {
      attributes: { exclude: ['password'] }
    });

    res.json({
      success: true,
      data: { user }
    });
  } catch (error) {
    console.error('Get user error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error'
    });
  }
});

// Logout (client-side token removal)
router.post('/logout', auth, (req, res) => {
  res.json({
    success: true,
    message: 'Logged out successfully'
  });
});

module.exports = router;