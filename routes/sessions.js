const express = require('express');
const { body, validationResult } = require('express-validator');
const { Session, Table, Order, User } = require('../models');
const { auth } = require('../middleware/auth');

const router = express.Router();

// Get all sessions
router.get('/', auth, async (req, res) => {
  try {
    const { status, table_id, customer_phone } = req.query;
    
    let whereClause = {};
    if (status) whereClause.status = status;
    if (table_id) whereClause.table_id = table_id;
    if (customer_phone) whereClause.customer_phone = customer_phone;

    const sessions = await Session.findAll({
      where: whereClause,
      include: [
        {
          model: Table,
          as: 'table'
        },
        {
          model: User,
          as: 'creator',
          attributes: ['id', 'name', 'username']
        }
      ],
      order: [['created_at', 'DESC']]
    });

    res.json({
      success: true,
      data: { sessions }
    });
  } catch (error) {
    console.error('Get sessions error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error'
    });
  }
});

// Get single session
router.get('/:id', auth, async (req, res) => {
  try {
    const session = await Session.findByPk(req.params.id, {
      include: [
        {
          model: Table,
          as: 'table'
        },
        {
          model: User,
          as: 'creator',
          attributes: ['id', 'name', 'username']
        }
      ]
    });

    if (!session) {
      return res.status(404).json({
        success: false,
        message: 'Session not found'
      });
    }

    // Get associated orders
    const orders = await Order.findAll({
      where: {
        table_id: session.table_id,
        created_at: {
          [Op.gte]: session.start_time,
          [Op.lte]: session.end_time || new Date()
        }
      }
    });

    res.json({
      success: true,
      data: { 
        session,
        orders
      }
    });
  } catch (error) {
    console.error('Get session error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error'
    });
  }
});

// Start session
router.post('/start', auth, [
  body('table_id').isInt().withMessage('Valid table ID is required'),
  body('customer_name').trim().notEmpty().withMessage('Customer name is required'),
  body('customer_phone').trim().notEmpty().withMessage('Customer phone is required')
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

    const { table_id, customer_name, customer_phone } = req.body;

    // Verify table exists and is available
    const table = await Table.findByPk(table_id);
    if (!table) {
      return res.status(404).json({
        success: false,
        message: 'Table not found'
      });
    }

    if (table.status !== 'available') {
      return res.status(400).json({
        success: false,
        message: 'Table is not available'
      });
    }

    // Create session
    const session = await Session.create({
      table_id,
      table_number: table.table_number,
      customer_name,
      customer_phone,
      hourly_rate: table.hourly_rate,
      created_by: req.user.id
    });

    // Update table status
    await table.update({
      status: 'occupied',
      current_session_id: session.id,
      session_start_time: session.start_time,
      customer_name,
      customer_phone
    });

    // Control smart plug if available
    if (table.plug_id) {
      await table.update({ plug_status: 'online' });
      // Here you would integrate with actual smart plug API
    }

    const completeSession = await Session.findByPk(session.id, {
      include: [
        {
          model: Table,
          as: 'table'
        }
      ]
    });

    res.status(201).json({
      success: true,
      message: 'Session started successfully',
      data: { session: completeSession }
    });
  } catch (error) {
    console.error('Start session error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error'
    });
  }
});

// End session
router.post('/:id/end', auth, async (req, res) => {
  try {
    const session = await Session.findByPk(req.params.id, {
      include: [
        {
          model: Table,
          as: 'table'
        }
      ]
    });

    if (!session) {
      return res.status(404).json({
        success: false,
        message: 'Session not found'
      });
    }

    if (session.status !== 'active') {
      return res.status(400).json({
        success: false,
        message: 'Session is not active'
      });
    }

    const endTime = new Date();
    const duration = Math.ceil((endTime - session.start_time) / (1000 * 60)); // minutes
    const sessionCost = (duration / 60) * session.hourly_rate;

    // Get total order cost for this session
    const orders = await Order.findAll({
      where: {
        table_id: session.table_id,
        created_at: {
          [Op.gte]: session.start_time,
          [Op.lte]: endTime
        }
      }
    });

    const totalOrderCost = orders.reduce((sum, order) => sum + parseFloat(order.total), 0);
    const subtotal = sessionCost + totalOrderCost;
    const tax = subtotal * 0.085; // 8.5% tax
    const serviceFee = subtotal * 0.05; // 5% service fee
    const total = subtotal + tax + serviceFee;

    // Update session
    await session.update({
      end_time: endTime,
      duration,
      session_cost: sessionCost,
      total_order_cost: totalOrderCost,
      subtotal,
      tax,
      service_fee: serviceFee,
      total,
      status: 'completed'
    });

    // Update table status
    await session.table.update({
      status: 'available',
      current_session_id: null,
      session_start_time: null,
      session_end_time: endTime,
      customer_name: null,
      customer_phone: null,
      plug_status: 'offline'
    });

    res.json({
      success: true,
      message: 'Session ended successfully',
      data: { session }
    });
  } catch (error) {
    console.error('End session error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error'
    });
  }
});

// Extend session
router.post('/:id/extend', auth, [
  body('minutes').isInt({ min: 1 }).withMessage('Extension time must be at least 1 minute')
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

    const { minutes, reason } = req.body;
    const session = await Session.findByPk(req.params.id);

    if (!session) {
      return res.status(404).json({
        success: false,
        message: 'Session not found'
      });
    }

    if (session.status !== 'active') {
      return res.status(400).json({
        success: false,
        message: 'Session is not active'
      });
    }

    // Add extension record
    const extensions = session.extensions || [];
    extensions.push({
      extendedBy: minutes,
      extendedAt: new Date(),
      reason: reason || 'Manual extension'
    });

    await session.update({ extensions });

    res.json({
      success: true,
      message: `Session extended by ${minutes} minutes`,
      data: { session }
    });
  } catch (error) {
    console.error('Extend session error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error'
    });
  }
});

// Pause session
router.post('/:id/pause', auth, async (req, res) => {
  try {
    const session = await Session.findByPk(req.params.id);

    if (!session) {
      return res.status(404).json({
        success: false,
        message: 'Session not found'
      });
    }

    if (session.status !== 'active') {
      return res.status(400).json({
        success: false,
        message: 'Session is not active'
      });
    }

    await session.update({ status: 'paused' });

    res.json({
      success: true,
      message: 'Session paused successfully',
      data: { session }
    });
  } catch (error) {
    console.error('Pause session error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error'
    });
  }
});

// Resume session
router.post('/:id/resume', auth, async (req, res) => {
  try {
    const session = await Session.findByPk(req.params.id);

    if (!session) {
      return res.status(404).json({
        success: false,
        message: 'Session not found'
      });
    }

    if (session.status !== 'paused') {
      return res.status(400).json({
        success: false,
        message: 'Session is not paused'
      });
    }

    await session.update({ status: 'active' });

    res.json({
      success: true,
      message: 'Session resumed successfully',
      data: { session }
    });
  } catch (error) {
    console.error('Resume session error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error'
    });
  }
});

// Get user's session history
router.get('/user/history', auth, async (req, res) => {
  try {
    const { customer_phone } = req.query;
    
    if (!customer_phone && req.user.role === 'User') {
      return res.status(400).json({
        success: false,
        message: 'Customer phone is required'
      });
    }

    let whereClause = { status: 'completed' };
    if (customer_phone) {
      whereClause.customer_phone = customer_phone;
    }

    const sessions = await Session.findAll({
      where: whereClause,
      include: [
        {
          model: Table,
          as: 'table'
        }
      ],
      order: [['created_at', 'DESC']],
      limit: 50
    });

    res.json({
      success: true,
      data: { sessions }
    });
  } catch (error) {
    console.error('Get session history error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error'
    });
  }
});

module.exports = router;