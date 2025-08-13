const express = require('express');
const { Order, OrderItem, MenuItem, Table } = require('../models');
const { auth } = require('../middleware/auth');

const router = express.Router();

// Get KOT queue
router.get('/queue', auth, async (req, res) => {
  try {
    const { status, printer } = req.query;
    
    let whereClause = {
      kot_printed: true,
      status: ['confirmed', 'preparing']
    };

    const orders = await Order.findAll({
      where: whereClause,
      include: [
        {
          model: OrderItem,
          as: 'items',
          include: [
            {
              model: MenuItem,
              as: 'menuItem',
              where: printer ? { printer } : {}
            }
          ],
          where: status ? { status } : {}
        },
        {
          model: Table,
          as: 'table'
        }
      ],
      order: [['kot_printed_at', 'ASC']]
    });

    // Filter out orders with no matching items
    const filteredOrders = orders.filter(order => order.items.length > 0);

    // Group by printer type
    const groupedByPrinter = {};
    filteredOrders.forEach(order => {
      order.items.forEach(item => {
        const printerType = item.menuItem.printer;
        if (!groupedByPrinter[printerType]) {
          groupedByPrinter[printerType] = [];
        }
        
        // Check if order already exists for this printer
        let existingOrder = groupedByPrinter[printerType].find(o => o.id === order.id);
        if (!existingOrder) {
          existingOrder = {
            ...order.toJSON(),
            items: []
          };
          groupedByPrinter[printerType].push(existingOrder);
        }
        
        existingOrder.items.push(item);
      });
    });

    res.json({
      success: true,
      data: { 
        orders: filteredOrders,
        groupedByPrinter
      }
    });
  } catch (error) {
    console.error('Get KOT queue error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error'
    });
  }
});

// Mark KOT item as complete
router.patch('/items/:itemId/complete', auth, async (req, res) => {
  try {
    const orderItem = await OrderItem.findByPk(req.params.itemId, {
      include: [
        {
          model: Order,
          as: 'order'
        }
      ]
    });

    if (!orderItem) {
      return res.status(404).json({
        success: false,
        message: 'Order item not found'
      });
    }

    await orderItem.update({ status: 'ready' });

    // Check if all items in the order are ready
    const allItems = await OrderItem.findAll({
      where: { order_id: orderItem.order_id }
    });

    const allReady = allItems.every(item => item.status === 'ready');
    if (allReady) {
      await Order.update(
        { status: 'ready' },
        { where: { id: orderItem.order_id } }
      );
    }

    res.json({
      success: true,
      message: 'Item marked as complete',
      data: { orderItem }
    });
  } catch (error) {
    console.error('Mark KOT item complete error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error'
    });
  }
});

// Mark entire KOT as complete
router.patch('/orders/:orderId/complete', auth, async (req, res) => {
  try {
    const order = await Order.findByPk(req.params.orderId);

    if (!order) {
      return res.status(404).json({
        success: false,
        message: 'Order not found'
      });
    }

    // Mark all items as ready
    await OrderItem.update(
      { status: 'ready' },
      { where: { order_id: order.id } }
    );

    // Mark order as ready
    await order.update({ status: 'ready' });

    res.json({
      success: true,
      message: 'Order marked as complete',
      data: { order }
    });
  } catch (error) {
    console.error('Mark KOT complete error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error'
    });
  }
});

// Get KOT statistics
router.get('/stats', auth, async (req, res) => {
  try {
    const today = new Date();
    today.setHours(0, 0, 0, 0);
    const tomorrow = new Date(today);
    tomorrow.setDate(tomorrow.getDate() + 1);

    // Get today's KOT stats
    const todayOrders = await Order.findAll({
      where: {
        kot_printed: true,
        created_at: {
          [Op.gte]: today,
          [Op.lt]: tomorrow
        }
      },
      include: [
        {
          model: OrderItem,
          as: 'items'
        }
      ]
    });

    const stats = {
      totalKOTs: todayOrders.length,
      completedKOTs: todayOrders.filter(o => o.status === 'ready' || o.status === 'served').length,
      pendingKOTs: todayOrders.filter(o => ['confirmed', 'preparing'].includes(o.status)).length,
      averageTime: 0, // Calculate based on your requirements
      printerStats: {}
    };

    // Calculate printer-wise stats
    const printerTypes = ['Kitchen Printer', 'Bar Printer', 'Main Printer', 'Game Zone Printer'];
    
    for (const printer of printerTypes) {
      const printerOrders = todayOrders.filter(order => 
        order.items.some(item => item.menuItem?.printer === printer)
      );
      
      stats.printerStats[printer] = {
        total: printerOrders.length,
        completed: printerOrders.filter(o => o.status === 'ready' || o.status === 'served').length,
        pending: printerOrders.filter(o => ['confirmed', 'preparing'].includes(o.status)).length
      };
    }

    res.json({
      success: true,
      data: { stats }
    });
  } catch (error) {
    console.error('Get KOT stats error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error'
    });
  }
});

module.exports = router;