const express = require('express');
const { body, validationResult } = require('express-validator');
const { Device, Table } = require('../models');
const { auth, authorize } = require('../middleware/auth');

const router = express.Router();

// Get all devices
router.get('/', auth, async (req, res) => {
  try {
    const { type, status, table_id } = req.query;
    
    let whereClause = { is_active: true };
    if (type) whereClause.type = type;
    if (status) whereClause.status = status;
    if (table_id) whereClause.table_id = table_id;

    const devices = await Device.findAll({
      where: whereClause,
      include: [
        {
          model: Table,
          as: 'table',
          required: false
        }
      ],
      order: [['name', 'ASC']]
    });

    res.json({
      success: true,
      data: { devices }
    });
  } catch (error) {
    console.error('Get devices error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error'
    });
  }
});

// Get single device
router.get('/:id', auth, async (req, res) => {
  try {
    const device = await Device.findByPk(req.params.id, {
      include: [
        {
          model: Table,
          as: 'table',
          required: false
        }
      ]
    });

    if (!device) {
      return res.status(404).json({
        success: false,
        message: 'Device not found'
      });
    }

    res.json({
      success: true,
      data: { device }
    });
  } catch (error) {
    console.error('Get device error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error'
    });
  }
});

// Create device (Admin/Manager only)
router.post('/', auth, authorize('Admin', 'Manager'), [
  body('device_id').trim().notEmpty().withMessage('Device ID is required'),
  body('name').trim().notEmpty().withMessage('Device name is required'),
  body('type').isIn(['smart_plug', 'light', 'tv', 'gaming_console', 'sound_system', 'other']).withMessage('Invalid device type'),
  body('location').trim().notEmpty().withMessage('Location is required')
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

    const { device_id, name, type, location, table_id, power_consumption } = req.body;

    // Check if device ID already exists
    const existingDevice = await Device.findOne({
      where: { device_id }
    });

    if (existingDevice) {
      return res.status(400).json({
        success: false,
        message: 'Device ID already exists'
      });
    }

    const device = await Device.create({
      device_id,
      name,
      type,
      location,
      table_id: table_id || null,
      power_consumption: power_consumption || null
    });

    const completeDevice = await Device.findByPk(device.id, {
      include: [
        {
          model: Table,
          as: 'table',
          required: false
        }
      ]
    });

    res.status(201).json({
      success: true,
      message: 'Device created successfully',
      data: { device: completeDevice }
    });
  } catch (error) {
    console.error('Create device error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error'
    });
  }
});

// Update device
router.put('/:id', auth, authorize('Admin', 'Manager'), async (req, res) => {
  try {
    const device = await Device.findByPk(req.params.id);
    if (!device) {
      return res.status(404).json({
        success: false,
        message: 'Device not found'
      });
    }

    const { device_id, name, type, location, table_id, power_consumption, status } = req.body;

    // Check if device ID already exists (excluding current device)
    if (device_id && device_id !== device.device_id) {
      const existingDevice = await Device.findOne({
        where: { device_id }
      });

      if (existingDevice) {
        return res.status(400).json({
          success: false,
          message: 'Device ID already exists'
        });
      }
    }

    await device.update({
      device_id: device_id || device.device_id,
      name: name || device.name,
      type: type || device.type,
      location: location || device.location,
      table_id: table_id !== undefined ? table_id : device.table_id,
      power_consumption: power_consumption !== undefined ? power_consumption : device.power_consumption,
      status: status || device.status,
      last_updated: new Date()
    });

    const updatedDevice = await Device.findByPk(device.id, {
      include: [
        {
          model: Table,
          as: 'table',
          required: false
        }
      ]
    });

    res.json({
      success: true,
      message: 'Device updated successfully',
      data: { device: updatedDevice }
    });
  } catch (error) {
    console.error('Update device error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error'
    });
  }
});

// Control device power
router.post('/:id/control', auth, [
  body('action').isIn(['on', 'off']).withMessage('Action must be on or off')
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

    const { action } = req.body;
    const device = await Device.findByPk(req.params.id);
    
    if (!device) {
      return res.status(404).json({
        success: false,
        message: 'Device not found'
      });
    }

    if (device.status === 'offline') {
      return res.status(400).json({
        success: false,
        message: 'Device is offline'
      });
    }

    // Here you would integrate with actual device control API
    // For now, we'll just update the power state
    await device.update({ 
      power_state: action,
      last_updated: new Date()
    });

    res.json({
      success: true,
      message: `Device turned ${action}`,
      data: { device }
    });
  } catch (error) {
    console.error('Control device error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error'
    });
  }
});

// Update device status
router.patch('/:id/status', auth, [
  body('status').isIn(['online', 'offline', 'maintenance']).withMessage('Invalid status')
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

    const { status } = req.body;
    const device = await Device.findByPk(req.params.id);
    
    if (!device) {
      return res.status(404).json({
        success: false,
        message: 'Device not found'
      });
    }

    await device.update({ 
      status,
      last_updated: new Date()
    });

    res.json({
      success: true,
      message: 'Device status updated successfully',
      data: { device }
    });
  } catch (error) {
    console.error('Update device status error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error'
    });
  }
});

// Get device statistics
router.get('/stats/overview', auth, async (req, res) => {
  try {
    const devices = await Device.findAll({
      where: { is_active: true }
    });

    const stats = {
      total: devices.length,
      online: devices.filter(d => d.status === 'online').length,
      offline: devices.filter(d => d.status === 'offline').length,
      maintenance: devices.filter(d => d.status === 'maintenance').length,
      byType: {}
    };

    // Group by type
    devices.forEach(device => {
      if (!stats.byType[device.type]) {
        stats.byType[device.type] = {
          total: 0,
          online: 0,
          offline: 0
        };
      }
      stats.byType[device.type].total++;
      if (device.status === 'online') stats.byType[device.type].online++;
      if (device.status === 'offline') stats.byType[device.type].offline++;
    });

    res.json({
      success: true,
      data: { stats }
    });
  } catch (error) {
    console.error('Get device stats error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error'
    });
  }
});

// Delete device (Admin only)
router.delete('/:id', auth, authorize('Admin'), async (req, res) => {
  try {
    const device = await Device.findByPk(req.params.id);
    if (!device) {
      return res.status(404).json({
        success: false,
        message: 'Device not found'
      });
    }

    await device.update({ is_active: false });

    res.json({
      success: true,
      message: 'Device deleted successfully'
    });
  } catch (error) {
    console.error('Delete device error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error'
    });
  }
});

module.exports = router;