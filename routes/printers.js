const express = require('express');
const { body, validationResult } = require('express-validator');
const Printer = require('../models/Printer');
const { auth, authorize } = require('../middleware/auth');

const router = express.Router();

// Get all printers
router.get('/', auth, async (req, res) => {
  try {
    const { type, status } = req.query;
    
    let whereClause = { is_active: true };
    if (type) whereClause.type = type;
    if (status) whereClause.status = status;

    const printers = await Printer.findAll({
      where: whereClause,
      order: [['name', 'ASC']]
    });

    res.json({
      success: true,
      data: { printers }
    });
  } catch (error) {
    console.error('Get printers error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error'
    });
  }
});

// Get single printer
router.get('/:id', auth, async (req, res) => {
  try {
    const printer = await Printer.findByPk(req.params.id);

    if (!printer) {
      return res.status(404).json({
        success: false,
        message: 'Printer not found'
      });
    }

    res.json({
      success: true,
      data: { printer }
    });
  } catch (error) {
    console.error('Get printer error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error'
    });
  }
});

// Create printer (Admin/Manager only)
router.post('/', auth, authorize('Admin', 'Manager'), [
  body('name').trim().notEmpty().withMessage('Printer name is required'),
  body('type').isIn(['Kitchen Printer', 'Bar Printer', 'Receipt Printer', 'Main Printer']).withMessage('Invalid printer type')
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

    const { name, type, ip_address, port } = req.body;

    const printer = await Printer.create({
      name,
      type,
      ip_address: ip_address || null,
      port: port || null
    });

    res.status(201).json({
      success: true,
      message: 'Printer created successfully',
      data: { printer }
    });
  } catch (error) {
    console.error('Create printer error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error'
    });
  }
});

// Update printer
router.put('/:id', auth, authorize('Admin', 'Manager'), async (req, res) => {
  try {
    const printer = await Printer.findByPk(req.params.id);
    if (!printer) {
      return res.status(404).json({
        success: false,
        message: 'Printer not found'
      });
    }

    const { name, type, ip_address, port, status } = req.body;

    await printer.update({
      name: name || printer.name,
      type: type || printer.type,
      ip_address: ip_address !== undefined ? ip_address : printer.ip_address,
      port: port !== undefined ? port : printer.port,
      status: status || printer.status
    });

    res.json({
      success: true,
      message: 'Printer updated successfully',
      data: { printer }
    });
  } catch (error) {
    console.error('Update printer error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error'
    });
  }
});

// Test printer
router.post('/:id/test', auth, async (req, res) => {
  try {
    const printer = await Printer.findByPk(req.params.id);
    
    if (!printer) {
      return res.status(404).json({
        success: false,
        message: 'Printer not found'
      });
    }

    if (!printer.is_active) {
      return res.status(400).json({
        success: false,
        message: 'Printer is not active'
      });
    }

    // Here you would integrate with actual printer API
    // For now, we'll just update the last test time
    await printer.update({ 
      last_test: new Date(),
      status: 'online' // Assume test is successful
    });

    res.json({
      success: true,
      message: 'Test print sent successfully',
      data: { printer }
    });
  } catch (error) {
    console.error('Test printer error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error'
    });
  }
});

// Toggle printer status
router.patch('/:id/toggle', auth, authorize('Admin', 'Manager'), async (req, res) => {
  try {
    const printer = await Printer.findByPk(req.params.id);
    
    if (!printer) {
      return res.status(404).json({
        success: false,
        message: 'Printer not found'
      });
    }

    await printer.update({ 
      is_active: !printer.is_active 
    });

    res.json({
      success: true,
      message: `Printer ${printer.is_active ? 'enabled' : 'disabled'} successfully`,
      data: { printer }
    });
  } catch (error) {
    console.error('Toggle printer error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error'
    });
  }
});

// Update printer status
router.patch('/:id/status', auth, [
  body('status').isIn(['online', 'offline', 'error']).withMessage('Invalid status')
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
    const printer = await Printer.findByPk(req.params.id);
    
    if (!printer) {
      return res.status(404).json({
        success: false,
        message: 'Printer not found'
      });
    }

    await printer.update({ status });

    res.json({
      success: true,
      message: 'Printer status updated successfully',
      data: { printer }
    });
  } catch (error) {
    console.error('Update printer status error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error'
    });
  }
});

// Get printer statistics
router.get('/stats/overview', auth, async (req, res) => {
  try {
    const printers = await Printer.findAll({
      where: { is_active: true }
    });

    const stats = {
      total: printers.length,
      online: printers.filter(p => p.status === 'online').length,
      offline: printers.filter(p => p.status === 'offline').length,
      error: printers.filter(p => p.status === 'error').length,
      byType: {}
    };

    // Group by type
    printers.forEach(printer => {
      if (!stats.byType[printer.type]) {
        stats.byType[printer.type] = {
          total: 0,
          online: 0,
          offline: 0,
          error: 0
        };
      }
      stats.byType[printer.type].total++;
      stats.byType[printer.type][printer.status]++;
    });

    res.json({
      success: true,
      data: { stats }
    });
  } catch (error) {
    console.error('Get printer stats error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error'
    });
  }
});

// Delete printer (Admin only)
router.delete('/:id', auth, authorize('Admin'), async (req, res) => {
  try {
    const printer = await Printer.findByPk(req.params.id);
    if (!printer) {
      return res.status(404).json({
        success: false,
        message: 'Printer not found'
      });
    }

    await printer.update({ is_active: false });

    res.json({
      success: true,
      message: 'Printer deleted successfully'
    });
  } catch (error) {
    console.error('Delete printer error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error'
    });
  }
});

module.exports = router;