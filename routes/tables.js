const express = require('express');
const { body, validationResult } = require('express-validator');
const { Table, Session, Device } = require('../models');
const { auth, authorize } = require('../middleware/auth');

const router = express.Router();

// Get all tables
router.get('/', auth, async (req, res) => {
  try {
    const { type, status } = req.query;
    
    let whereClause = { is_active: true };
    if (type) whereClause.type = type;
    if (status) whereClause.status = status;

    const tables = await Table.findAll({
      where: whereClause,
      include: [
        {
          model: Session,
          as: 'currentSession',
          required: false
        },
        {
          model: Device,
          as: 'devices',
          required: false
        }
      ],
      order: [['table_number', 'ASC']]
    });

    res.json({
      success: true,
      data: { tables }
    });
  } catch (error) {
    console.error('Get tables error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error'
    });
  }
});

// Get single table
router.get('/:id', auth, async (req, res) => {
  try {
    const table = await Table.findByPk(req.params.id, {
      include: [
        {
          model: Session,
          as: 'currentSession',
          required: false
        },
        {
          model: Device,
          as: 'devices',
          required: false
        }
      ]
    });

    if (!table) {
      return res.status(404).json({
        success: false,
        message: 'Table not found'
      });
    }

    res.json({
      success: true,
      data: { table }
    });
  } catch (error) {
    console.error('Get table error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error'
    });
  }
});

// Create table (Admin/Manager only)
router.post('/', auth, authorize('Admin', 'Manager'), [
  body('table_number').trim().notEmpty().withMessage('Table number is required'),
  body('name').trim().notEmpty().withMessage('Table name is required'),
  body('type').isIn(['Snooker', 'Pool', 'PlayStation', 'Restaurant', 'Dining', 'Food']).withMessage('Invalid table type'),
  body('location').trim().notEmpty().withMessage('Location is required'),
  body('capacity').isInt({ min: 1 }).withMessage('Capacity must be at least 1'),
  body('hourly_rate').isFloat({ min: 0 }).withMessage('Hourly rate must be a positive number')
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

    const { table_number, name, type, location, capacity, hourly_rate, plug_id, features } = req.body;

    // Check if table number already exists
    const existingTable = await Table.findOne({
      where: { table_number }
    });

    if (existingTable) {
      return res.status(400).json({
        success: false,
        message: 'Table number already exists'
      });
    }

    const table = await Table.create({
      table_number,
      name,
      type,
      location,
      capacity,
      hourly_rate,
      plug_id,
      features: features || []
    });

    res.status(201).json({
      success: true,
      message: 'Table created successfully',
      data: { table }
    });
  } catch (error) {
    console.error('Create table error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error'
    });
  }
});

// Update table
router.put('/:id', auth, authorize('Admin', 'Manager'), async (req, res) => {
  try {
    const table = await Table.findByPk(req.params.id);
    if (!table) {
      return res.status(404).json({
        success: false,
        message: 'Table not found'
      });
    }

    const { table_number, name, type, location, capacity, hourly_rate, plug_id, features, status } = req.body;

    // Check if table number already exists (excluding current table)
    if (table_number && table_number !== table.table_number) {
      const existingTable = await Table.findOne({
        where: { table_number }
      });

      if (existingTable) {
        return res.status(400).json({
          success: false,
          message: 'Table number already exists'
        });
      }
    }

    await table.update({
      table_number: table_number || table.table_number,
      name: name || table.name,
      type: type || table.type,
      location: location || table.location,
      capacity: capacity || table.capacity,
      hourly_rate: hourly_rate || table.hourly_rate,
      plug_id: plug_id !== undefined ? plug_id : table.plug_id,
      features: features || table.features,
      status: status || table.status
    });

    res.json({
      success: true,
      message: 'Table updated successfully',
      data: { table }
    });
  } catch (error) {
    console.error('Update table error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error'
    });
  }
});

// Update table status
router.patch('/:id/status', auth, async (req, res) => {
  try {
    const { status } = req.body;
    
    if (!['available', 'occupied', 'reserved', 'maintenance'].includes(status)) {
      return res.status(400).json({
        success: false,
        message: 'Invalid status'
      });
    }

    const table = await Table.findByPk(req.params.id);
    if (!table) {
      return res.status(404).json({
        success: false,
        message: 'Table not found'
      });
    }

    await table.update({ status });

    res.json({
      success: true,
      message: 'Table status updated successfully',
      data: { table }
    });
  } catch (error) {
    console.error('Update table status error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error'
    });
  }
});

// Map smart plug to table
router.post('/:id/plug', auth, authorize('Admin', 'Manager'), [
  body('plug_id').trim().notEmpty().withMessage('Plug ID is required')
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

    const { plug_id } = req.body;
    const table = await Table.findByPk(req.params.id);
    
    if (!table) {
      return res.status(404).json({
        success: false,
        message: 'Table not found'
      });
    }

    await table.update({ 
      plug_id,
      plug_status: 'offline'
    });

    res.json({
      success: true,
      message: 'Smart plug mapped successfully',
      data: { table }
    });
  } catch (error) {
    console.error('Map plug error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error'
    });
  }
});

// Control smart plug
router.post('/:id/plug/control', auth, [
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
    const table = await Table.findByPk(req.params.id);
    
    if (!table || !table.plug_id) {
      return res.status(404).json({
        success: false,
        message: 'Table or smart plug not found'
      });
    }

    // Here you would integrate with actual smart plug API
    // For now, we'll just update the status
    await table.update({ 
      plug_status: action === 'on' ? 'online' : 'offline'
    });

    res.json({
      success: true,
      message: `Smart plug turned ${action}`,
      data: { table }
    });
  } catch (error) {
    console.error('Control plug error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error'
    });
  }
});

// Delete table (Admin only)
router.delete('/:id', auth, authorize('Admin'), async (req, res) => {
  try {
    const table = await Table.findByPk(req.params.id);
    if (!table) {
      return res.status(404).json({
        success: false,
        message: 'Table not found'
      });
    }

    // Check if table has active sessions
    if (table.status === 'occupied') {
      return res.status(400).json({
        success: false,
        message: 'Cannot delete table with active session'
      });
    }

    await table.update({ is_active: false });

    res.json({
      success: true,
      message: 'Table deleted successfully'
    });
  } catch (error) {
    console.error('Delete table error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error'
    });
  }
});

module.exports = router;