const express = require('express');
const { body, validationResult } = require('express-validator');
const User = require('../models/User');
const { auth, authorize } = require('../middleware/auth');

const router = express.Router();

// Get all staff members (Admin only)
router.get('/staff', auth, authorize('Admin'), async (req, res) => {
  try {
    const staff = await User.findAll({
      where: {
        role: ['Staff', 'Manager'],
        is_active: true
      },
      attributes: { exclude: ['password'] },
      order: [['createdAt', 'DESC']]
    });

    res.json({
      success: true,
      data: { staff }
    });
  } catch (error) {
    console.error('Get staff error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error'
    });
  }
});

// Create staff member (Admin only)
router.post('/staff', auth, authorize('Admin'), [
  body('firstName'),
  body('lastName'),
  body('email').isEmail().withMessage('Please provide a valid email'),
  body('password').isLength({ min: 3 }).withMessage('Password must be at least 3 characters'),
  body('role').isIn(['Staff', 'Manager']).withMessage('Invalid role')
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

    const { firstName, lastName, email, password, role } = req.body;

    // Check if user already exists
    const existingUser = await User.findOne({
      where: { email }
    });

    if (existingUser) {
      return res.status(400).json({
        success: false,
        message: 'User with this email already exists'
      });
    }

    // Set permissions based on role
    let permissions = {};
    if (role === 'Manager') {
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
    } else {
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

    const user = await User.create({
      firstName,
      lastName,
      email,
      password,
      role,
      permissions
    });

    res.status(201).json({
      success: true,
      message: 'Staff member created successfully',
      data: {
        user: {
          id: user.id,
          firstName: user.firstName,
          lastName: user.lastName,
          email: user.email,
          role: user.role,
          permissions: user.permissions
        }
      }
    });
  } catch (error) {
    console.error('Create staff error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error'
    });
  }
});

// Update staff member (Admin only)
router.put('/staff/:id', auth, authorize('Admin'), [
  body('firstName'),
  body('lastName'),
  body('email').optional().isEmail().withMessage('Please provide a valid email'),
  body('role').optional().isIn(['Staff', 'Manager']).withMessage('Invalid role')
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

    const { id } = req.params;
    const { firstName, lastName, email, role } = req.body;

    const user = await User.findByPk(id);
    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }

    // Check if email is being updated and if it already exists
    if (email && email !== user.email) {
      const existingUser = await User.findOne({ where: { email } });
      if (existingUser) {
        return res.status(400).json({
          success: false,
          message: 'Email already in use by another user'
        });
      }
    }

    // Prepare update data
    const updateData = {};
    if (firstName) updateData.firstName = firstName;
    if (lastName) updateData.lastName = lastName;
    if (email) updateData.email = email;
    if (role) updateData.role = role;

    await user.update(updateData);

    res.json({
      success: true,
      message: 'Staff member updated successfully',
      data: {
        user: {
          id: user.id,
          firstName: user.firstName,
          lastName: user.lastName,
          email: user.email,
          role: user.role
        }
      }
    });
  } catch (error) {
    console.error('Update staff error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error'
    });
  }
});

// Update staff permissions (Admin only)
router.put('/staff/:id/permissions', auth, authorize('Admin'), async (req, res) => {
  try {
    const { id } = req.params;
    const { permissions } = req.body;

    const user = await User.findByPk(id);
    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }

    if (user.role === 'Admin') {
      return res.status(400).json({
        success: false,
        message: 'Cannot modify admin permissions'
      });
    }

    await user.update({ permissions });

    res.json({
      success: true,
      message: 'Permissions updated successfully',
      data: {
        user: {
          id: user.id,
          firstName: user.firstName,
          lastName: user.lastName,
          permissions: user.permissions
        }
      }
    });
  } catch (error) {
    console.error('Update permissions error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error'
    });
  }
});

// Delete staff member (Admin only)
router.delete('/staff/:id', auth, authorize('Admin'), async (req, res) => {
  try {
    const { id } = req.params;

    const user = await User.findByPk(id);
    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }

    if (user.role === 'Admin') {
      return res.status(400).json({
        success: false,
        message: 'Cannot delete admin user'
      });
    }

    await user.update({ is_active: false });

    res.json({
      success: true,
      message: 'Staff member deactivated successfully'
    });
  } catch (error) {
    console.error('Delete staff error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error'
    });
  }
});

// Get user profile (Authenticated users)
router.get('/profile', auth, async (req, res) => {
  try {
    const user = await User.findByPk(req.user.id, {
      attributes: { exclude: ['password'] }
    });

    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }

    res.json({
      success: true,
      data: {
        user: {
          id: user.id,
          firstName: user.firstName,
          lastName: user.lastName,
          email: user.email,
          role: user.role,
          permissions: user.permissions
        }
      }
    });
  } catch (error) {
    console.error('Get profile error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error'
    });
  }
});

// Update user profile (Authenticated users)
router.put('/profile', auth, [
  body('firstName').optional().trim().isLength({ min: 2 }).withMessage('First name must be at least 2 characters'),
  body('lastName').optional().trim().isLength({ min: 2 }).withMessage('Last name must be at least 2 characters'),
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

    const { firstName, lastName } = req.body;
    const user = await User.findByPk(req.user.id);

    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }

    // Prepare update data
    const updateData = {};
    if (firstName) updateData.firstName = firstName;
    if (lastName) updateData.lastName = lastName;

    await user.update(updateData);

    res.json({
      success: true,
      message: 'Profile updated successfully',
      data: {
        user: {
          id: user.id,
          firstName: user.firstName,
          lastName: user.lastName,
          email: user.email,
        }
      }
    });
  } catch (error) {
    console.error('Update profile error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error'
    });
  }
});

module.exports = router;