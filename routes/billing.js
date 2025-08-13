const express = require('express');
const { body, validationResult } = require('express-validator');
const { Session, Order, OrderItem, Table } = require('../models');
const { auth } = require('../middleware/auth');

const router = express.Router();

// Get session bill
router.get('/session/:sessionId', auth, async (req, res) => {
  try {
    const session = await Session.findByPk(req.params.sessionId, {
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

    // Get all orders for this session
    const orders = await Order.findAll({
      where: {
        table_id: session.table_id,
        created_at: {
          [Op.gte]: session.start_time,
          [Op.lte]: session.end_time || new Date()
        }
      },
      include: [
        {
          model: OrderItem,
          as: 'items',
          include: [
            {
              model: MenuItem,
              as: 'menuItem'
            }
          ]
        }
      ]
    });

    // Calculate current session cost if still active
    let currentSessionCost = session.session_cost;
    if (session.status === 'active') {
      const currentTime = new Date();
      const duration = Math.ceil((currentTime - session.start_time) / (1000 * 60)); // minutes
      currentSessionCost = (duration / 60) * session.hourly_rate;
    }

    const bill = {
      session: {
        ...session.toJSON(),
        current_session_cost: currentSessionCost
      },
      orders,
      summary: {
        session_cost: currentSessionCost,
        orders_cost: orders.reduce((sum, order) => sum + parseFloat(order.total), 0),
        subtotal: session.subtotal || 0,
        tax: session.tax || 0,
        service_fee: session.service_fee || 0,
        discount: session.discount || 0,
        total: session.total || 0
      }
    };

    res.json({
      success: true,
      data: { bill }
    });
  } catch (error) {
    console.error('Get session bill error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error'
    });
  }
});

// Apply discount to session
router.post('/session/:sessionId/discount', auth, [
  body('discount_type').isIn(['percentage', 'fixed']).withMessage('Invalid discount type'),
  body('discount_value').isFloat({ min: 0 }).withMessage('Discount value must be positive')
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

    const { discount_type, discount_value, reason } = req.body;
    const session = await Session.findByPk(req.params.sessionId);

    if (!session) {
      return res.status(404).json({
        success: false,
        message: 'Session not found'
      });
    }

    // Check user permissions for discount
    const userPermissions = req.user.permissions?.specialPermissions?.discounts;
    if (!userPermissions?.item && !userPermissions?.bill) {
      return res.status(403).json({
        success: false,
        message: 'Insufficient permissions to apply discount'
      });
    }

    // Check maximum discount limit
    const maxDiscount = userPermissions?.maxDiscount || 0;
    if (discount_type === 'percentage' && discount_value > maxDiscount) {
      return res.status(400).json({
        success: false,
        message: `Maximum discount allowed is ${maxDiscount}%`
      });
    }

    // Calculate discount amount
    const subtotal = session.subtotal || 0;
    let discountAmount = 0;
    
    if (discount_type === 'percentage') {
      discountAmount = (subtotal * discount_value) / 100;
    } else {
      discountAmount = discount_value;
    }

    // Recalculate total
    const tax = session.tax || 0;
    const serviceFee = session.service_fee || 0;
    const newTotal = subtotal + tax + serviceFee - discountAmount;

    await session.update({
      discount: discountAmount,
      total: Math.max(0, newTotal) // Ensure total is not negative
    });

    res.json({
      success: true,
      message: 'Discount applied successfully',
      data: { 
        session,
        discount_applied: discountAmount,
        new_total: newTotal
      }
    });
  } catch (error) {
    console.error('Apply discount error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error'
    });
  }
});

// Process payment
router.post('/session/:sessionId/payment', auth, [
  body('payment_method').isIn(['cash', 'card', 'upi', 'online']).withMessage('Invalid payment method'),
  body('amount_paid').isFloat({ min: 0 }).withMessage('Amount paid must be positive')
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

    const { payment_method, amount_paid } = req.body;
    const session = await Session.findByPk(req.params.sessionId, {
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

    if (session.payment_status === 'paid') {
      return res.status(400).json({
        success: false,
        message: 'Session already paid'
      });
    }

    // Update session payment status
    await session.update({
      payment_status: 'paid',
      payment_method
    });

    // If session is still active, end it
    if (session.status === 'active') {
      const endTime = new Date();
      const duration = Math.ceil((endTime - session.start_time) / (1000 * 60)); // minutes
      const sessionCost = (duration / 60) * session.hourly_rate;

      await session.update({
        end_time: endTime,
        duration,
        session_cost: sessionCost,
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
    }

    // Mark all associated orders as paid
    await Order.update(
      { payment_status: 'paid' },
      {
        where: {
          table_id: session.table_id,
          created_at: {
            [Op.gte]: session.start_time,
            [Op.lte]: session.end_time || new Date()
          }
        }
      }
    );

    res.json({
      success: true,
      message: 'Payment processed successfully',
      data: { session }
    });
  } catch (error) {
    console.error('Process payment error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error'
    });
  }
});

// Get user's billing history
router.get('/user/history', async (req, res) => {
  try {
    const { customer_phone } = req.query;
    
    if (!customer_phone) {
      return res.status(400).json({
        success: false,
        message: 'Customer phone is required'
      });
    }

    const sessions = await Session.findAll({
      where: { 
        customer_phone,
        payment_status: 'paid'
      },
      include: [
        {
          model: Table,
          as: 'table'
        }
      ],
      order: [['created_at', 'DESC']],
      limit: 20
    });

    res.json({
      success: true,
      data: { sessions }
    });
  } catch (error) {
    console.error('Get billing history error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error'
    });
  }
});

// Generate receipt
router.get('/session/:sessionId/receipt', auth, async (req, res) => {
  try {
    const session = await Session.findByPk(req.params.sessionId, {
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

    // Get all orders for this session
    const orders = await Order.findAll({
      where: {
        table_id: session.table_id,
        created_at: {
          [Op.gte]: session.start_time,
          [Op.lte]: session.end_time || new Date()
        }
      },
      include: [
        {
          model: OrderItem,
          as: 'items',
          include: [
            {
              model: MenuItem,
              as: 'menuItem'
            }
          ]
        }
      ]
    });

    const receipt = {
      session_id: session.session_id,
      table: session.table.name,
      customer: {
        name: session.customer_name,
        phone: session.customer_phone
      },
      timing: {
        start_time: session.start_time,
        end_time: session.end_time,
        duration: session.duration
      },
      session_charges: {
        hourly_rate: session.hourly_rate,
        duration_hours: (session.duration / 60).toFixed(2),
        session_cost: session.session_cost
      },
      orders: orders.map(order => ({
        order_id: order.order_id,
        items: order.items.map(item => ({
          name: item.name,
          quantity: item.quantity,
          price: item.price,
          total: item.quantity * item.price
        })),
        total: order.total
      })),
      billing: {
        subtotal: session.subtotal,
        tax: session.tax,
        service_fee: session.service_fee,
        discount: session.discount,
        total: session.total
      },
      payment: {
        method: session.payment_method,
        status: session.payment_status,
        paid_at: session.updated_at
      }
    };

    res.json({
      success: true,
      data: { receipt }
    });
  } catch (error) {
    console.error('Generate receipt error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error'
    });
  }
});

module.exports = router;