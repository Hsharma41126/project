const express = require('express');
const { body, validationResult } = require('express-validator');
const { Order, OrderItem, MenuItem, Table, User } = require('../models');
const { auth } = require('../middleware/auth');

const router = express.Router();

// Get all orders
router.get('/', auth, async (req, res) => {
  try {
    const { status, table_id, date } = req.query;
    
    let whereClause = {};
    if (status) whereClause.status = status;
    if (table_id) whereClause.table_id = table_id;
    if (date) {
      const startDate = new Date(date);
      const endDate = new Date(date);
      endDate.setDate(endDate.getDate() + 1);
      whereClause.created_at = {
        [Op.gte]: startDate,
        [Op.lt]: endDate
      };
    }

    const orders = await Order.findAll({
      where: whereClause,
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
        },
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
      data: { orders }
    });
  } catch (error) {
    console.error('Get orders error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error'
    });
  }
});

// Get single order
router.get('/:id', auth, async (req, res) => {
  try {
    const order = await Order.findByPk(req.params.id, {
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
        },
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

    if (!order) {
      return res.status(404).json({
        success: false,
        message: 'Order not found'
      });
    }

    res.json({
      success: true,
      data: { order }
    });
  } catch (error) {
    console.error('Get order error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error'
    });
  }
});

// Create order
router.post('/', auth, [
  body('table_id').isInt().withMessage('Valid table ID is required'),
  body('customer_name').trim().notEmpty().withMessage('Customer name is required'),
  body('customer_phone').trim().notEmpty().withMessage('Customer phone is required'),
  body('order_type').isIn(['food', 'drinks', 'games', 'mixed']).withMessage('Invalid order type'),
  body('items').isArray({ min: 1 }).withMessage('At least one item is required'),
  body('items.*.menu_item_id').isInt().withMessage('Valid menu item ID is required'),
  body('items.*.quantity').isInt({ min: 1 }).withMessage('Quantity must be at least 1')
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

    const {
      table_id,
      customer_name,
      customer_phone,
      service_type = 'dine-in',
      order_type,
      items,
      special_instructions
    } = req.body;

    // Verify table exists
    const table = await Table.findByPk(table_id);
    if (!table) {
      return res.status(404).json({
        success: false,
        message: 'Table not found'
      });
    }

    // Calculate totals
    let subtotal = 0;
    const orderItems = [];

    for (const item of items) {
      const menuItem = await MenuItem.findByPk(item.menu_item_id);
      if (!menuItem || !menuItem.is_available) {
        return res.status(400).json({
          success: false,
          message: `Menu item ${menuItem ? menuItem.name : 'with ID ' + item.menu_item_id} is not available`
        });
      }

      const itemTotal = menuItem.price * item.quantity;
      subtotal += itemTotal;

      orderItems.push({
        menu_item_id: menuItem.id,
        name: menuItem.name,
        price: menuItem.price,
        quantity: item.quantity,
        special_instructions: item.special_instructions
      });
    }

    const tax = subtotal * 0.085; // 8.5% tax
    const total = subtotal + tax;

    // Create order
    const order = await Order.create({
      table_id,
      table_number: table.table_number,
      customer_name,
      customer_phone,
      service_type,
      order_type,
      subtotal,
      tax,
      total,
      created_by: req.user.id,
      special_instructions
    });

    // Create order items
    for (const item of orderItems) {
      await OrderItem.create({
        order_id: order.id,
        ...item
      });
    }

    // Fetch complete order with items
    const completeOrder = await Order.findByPk(order.id, {
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
        },
        {
          model: Table,
          as: 'table'
        }
      ]
    });

    res.status(201).json({
      success: true,
      message: 'Order created successfully',
      data: { order: completeOrder }
    });
  } catch (error) {
    console.error('Create order error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error'
    });
  }
});

// Update order status
router.patch('/:id/status', auth, [
  body('status').isIn(['pending', 'confirmed', 'preparing', 'ready', 'served', 'cancelled']).withMessage('Invalid status')
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
    const order = await Order.findByPk(req.params.id);

    if (!order) {
      return res.status(404).json({
        success: false,
        message: 'Order not found'
      });
    }

    await order.update({ status });

    res.json({
      success: true,
      message: 'Order status updated successfully',
      data: { order }
    });
  } catch (error) {
    console.error('Update order status error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error'
    });
  }
});

// Update order item status
router.patch('/:orderId/items/:itemId/status', auth, [
  body('status').isIn(['pending', 'preparing', 'ready', 'served']).withMessage('Invalid status')
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
    const { orderId, itemId } = req.params;

    const orderItem = await OrderItem.findOne({
      where: {
        id: itemId,
        order_id: orderId
      }
    });

    if (!orderItem) {
      return res.status(404).json({
        success: false,
        message: 'Order item not found'
      });
    }

    await orderItem.update({ status });

    res.json({
      success: true,
      message: 'Order item status updated successfully',
      data: { orderItem }
    });
  } catch (error) {
    console.error('Update order item status error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error'
    });
  }
});

// Print KOT
router.post('/:id/kot', auth, async (req, res) => {
  try {
    const order = await Order.findByPk(req.params.id, {
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
        },
        {
          model: Table,
          as: 'table'
        }
      ]
    });

    if (!order) {
      return res.status(404).json({
        success: false,
        message: 'Order not found'
      });
    }

    // Update KOT printed status
    await order.update({
      kot_printed: true,
      kot_printed_at: new Date()
    });

    // Here you would integrate with actual printer
    // For now, we'll just return success

    res.json({
      success: true,
      message: 'KOT printed successfully',
      data: { order }
    });
  } catch (error) {
    console.error('Print KOT error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error'
    });
  }
});

// Cancel order
router.delete('/:id', auth, async (req, res) => {
  try {
    const order = await Order.findByPk(req.params.id);
    if (!order) {
      return res.status(404).json({
        success: false,
        message: 'Order not found'
      });
    }

    if (order.status === 'served') {
      return res.status(400).json({
        success: false,
        message: 'Cannot cancel served order'
      });
    }

    await order.update({ status: 'cancelled' });

    res.json({
      success: true,
      message: 'Order cancelled successfully'
    });
  } catch (error) {
    console.error('Cancel order error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error'
    });
  }
});

module.exports = router;