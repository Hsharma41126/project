const express = require('express');
const { Op } = require('sequelize');
const { Session, Order, OrderItem, MenuItem, Table, User } = require('../models');
const { auth, authorize } = require('../middleware/auth');

const router = express.Router();

// Get dashboard analytics
router.get('/dashboard', auth, authorize('Admin', 'Manager'), async (req, res) => {
  try {
    const today = new Date();
    today.setHours(0, 0, 0, 0);
    const tomorrow = new Date(today);
    tomorrow.setDate(tomorrow.getDate() + 1);

    // Get today's stats
    const todaySessions = await Session.findAll({
      where: {
        created_at: {
          [Op.gte]: today,
          [Op.lt]: tomorrow
        }
      }
    });

    const todayOrders = await Order.findAll({
      where: {
        created_at: {
          [Op.gte]: today,
          [Op.lt]: tomorrow
        }
      }
    });

    // Calculate revenue
    const totalRevenue = todaySessions.reduce((sum, session) => sum + parseFloat(session.total || 0), 0);
    const tableRevenue = todaySessions.reduce((sum, session) => sum + parseFloat(session.session_cost || 0), 0);
    const orderRevenue = todayOrders.reduce((sum, order) => sum + parseFloat(order.total || 0), 0);
    const discounts = todaySessions.reduce((sum, session) => sum + parseFloat(session.discount || 0), 0);

    // Session stats
    const totalSessions = todaySessions.length;
    const activeSessions = todaySessions.filter(s => s.status === 'active').length;
    const completedSessions = todaySessions.filter(s => s.status === 'completed').length;

    // Average duration
    const completedSessionsWithDuration = todaySessions.filter(s => s.duration > 0);
    const avgDuration = completedSessionsWithDuration.length > 0 
      ? completedSessionsWithDuration.reduce((sum, s) => sum + s.duration, 0) / completedSessionsWithDuration.length 
      : 0;

    // Peak usage time (simplified)
    const peakHour = 20; // 8 PM as default

    const analytics = {
      revenue: {
        total: totalRevenue,
        table: tableRevenue,
        orders: orderRevenue,
        discounts: discounts
      },
      sessions: {
        total: totalSessions,
        active: activeSessions,
        completed: completedSessions,
        avgDuration: Math.round(avgDuration),
        peakHour: `${peakHour}:00`
      },
      orders: {
        total: todayOrders.length,
        pending: todayOrders.filter(o => o.status === 'pending').length,
        completed: todayOrders.filter(o => o.status === 'served').length
      }
    };

    res.json({
      success: true,
      data: { analytics }
    });
  } catch (error) {
    console.error('Get dashboard analytics error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error'
    });
  }
});

// Get revenue by category
router.get('/revenue/category', auth, authorize('Admin', 'Manager'), async (req, res) => {
  try {
    const { startDate, endDate } = req.query;
    
    let dateFilter = {};
    if (startDate && endDate) {
      dateFilter = {
        created_at: {
          [Op.gte]: new Date(startDate),
          [Op.lte]: new Date(endDate)
        }
      };
    }

    const orders = await Order.findAll({
      where: dateFilter,
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

    const categoryRevenue = {};
    
    orders.forEach(order => {
      order.items.forEach(item => {
        const category = item.menuItem.category;
        const itemTotal = item.quantity * item.price;
        
        if (!categoryRevenue[category]) {
          categoryRevenue[category] = 0;
        }
        categoryRevenue[category] += itemTotal;
      });
    });

    res.json({
      success: true,
      data: { categoryRevenue }
    });
  } catch (error) {
    console.error('Get category revenue error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error'
    });
  }
});

// Get table performance
router.get('/tables/performance', auth, authorize('Admin', 'Manager'), async (req, res) => {
  try {
    const { startDate, endDate } = req.query;
    
    let dateFilter = {};
    if (startDate && endDate) {
      dateFilter = {
        created_at: {
          [Op.gte]: new Date(startDate),
          [Op.lte]: new Date(endDate)
        }
      };
    }

    const sessions = await Session.findAll({
      where: dateFilter,
      include: [
        {
          model: Table,
          as: 'table'
        }
      ]
    });

    const tablePerformance = {};
    
    sessions.forEach(session => {
      const tableId = session.table_id;
      const tableName = session.table.name;
      
      if (!tablePerformance[tableId]) {
        tablePerformance[tableId] = {
          name: tableName,
          type: session.table.type,
          totalRevenue: 0,
          totalSessions: 0,
          totalDuration: 0,
          avgDuration: 0,
          occupancyRate: 0
        };
      }
      
      tablePerformance[tableId].totalRevenue += parseFloat(session.total || 0);
      tablePerformance[tableId].totalSessions += 1;
      tablePerformance[tableId].totalDuration += session.duration || 0;
    });

    // Calculate averages
    Object.keys(tablePerformance).forEach(tableId => {
      const table = tablePerformance[tableId];
      table.avgDuration = table.totalSessions > 0 ? Math.round(table.totalDuration / table.totalSessions) : 0;
      // Simplified occupancy rate calculation
      table.occupancyRate = Math.min(100, (table.totalSessions * 2)); // Assuming 2 hours average session
    });

    res.json({
      success: true,
      data: { tablePerformance: Object.values(tablePerformance) }
    });
  } catch (error) {
    console.error('Get table performance error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error'
    });
  }
});

// Get item sales report
router.get('/items/sales', auth, authorize('Admin', 'Manager'), async (req, res) => {
  try {
    const { startDate, endDate } = req.query;
    
    let dateFilter = {};
    if (startDate && endDate) {
      dateFilter = {
        created_at: {
          [Op.gte]: new Date(startDate),
          [Op.lte]: new Date(endDate)
        }
      };
    }

    const orderItems = await OrderItem.findAll({
      include: [
        {
          model: Order,
          as: 'order',
          where: dateFilter
        },
        {
          model: MenuItem,
          as: 'menuItem'
        }
      ]
    });

    const itemSales = {};
    
    orderItems.forEach(item => {
      const itemId = item.menu_item_id;
      const itemName = item.menuItem.name;
      
      if (!itemSales[itemId]) {
        itemSales[itemId] = {
          name: itemName,
          category: item.menuItem.category,
          subcategory: item.menuItem.subcategory,
          quantitySold: 0,
          totalRevenue: 0,
          avgPrice: item.menuItem.price
        };
      }
      
      itemSales[itemId].quantitySold += item.quantity;
      itemSales[itemId].totalRevenue += item.quantity * item.price;
    });

    // Sort by quantity sold
    const sortedItems = Object.values(itemSales).sort((a, b) => b.quantitySold - a.quantitySold);

    res.json({
      success: true,
      data: { itemSales: sortedItems }
    });
  } catch (error) {
    console.error('Get item sales error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error'
    });
  }
});

// Get staff performance
router.get('/staff/performance', auth, authorize('Admin'), async (req, res) => {
  try {
    const { startDate, endDate } = req.query;
    
    let dateFilter = {};
    if (startDate && endDate) {
      dateFilter = {
        created_at: {
          [Op.gte]: new Date(startDate),
          [Op.lte]: new Date(endDate)
        }
      };
    }

    const orders = await Order.findAll({
      where: dateFilter,
      include: [
        {
          model: User,
          as: 'creator',
          attributes: ['id', 'name', 'username', 'role']
        }
      ]
    });

    const sessions = await Session.findAll({
      where: dateFilter,
      include: [
        {
          model: User,
          as: 'creator',
          attributes: ['id', 'name', 'username', 'role']
        }
      ]
    });

    const staffPerformance = {};
    
    // Process orders
    orders.forEach(order => {
      const staffId = order.created_by;
      const staffName = order.creator.name;
      
      if (!staffPerformance[staffId]) {
        staffPerformance[staffId] = {
          name: staffName,
          role: order.creator.role,
          ordersHandled: 0,
          sessionsHandled: 0,
          totalSales: 0
        };
      }
      
      staffPerformance[staffId].ordersHandled += 1;
      staffPerformance[staffId].totalSales += parseFloat(order.total || 0);
    });

    // Process sessions
    sessions.forEach(session => {
      const staffId = session.created_by;
      const staffName = session.creator.name;
      
      if (!staffPerformance[staffId]) {
        staffPerformance[staffId] = {
          name: staffName,
          role: session.creator.role,
          ordersHandled: 0,
          sessionsHandled: 0,
          totalSales: 0
        };
      }
      
      staffPerformance[staffId].sessionsHandled += 1;
      staffPerformance[staffId].totalSales += parseFloat(session.total || 0);
    });

    res.json({
      success: true,
      data: { staffPerformance: Object.values(staffPerformance) }
    });
  } catch (error) {
    console.error('Get staff performance error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error'
    });
  }
});

// Get financial summary
router.get('/financial/summary', auth, authorize('Admin', 'Manager'), async (req, res) => {
  try {
    const { startDate, endDate } = req.query;
    
    let dateFilter = {};
    if (startDate && endDate) {
      dateFilter = {
        created_at: {
          [Op.gte]: new Date(startDate),
          [Op.lte]: new Date(endDate)
        }
      };
    }

    const sessions = await Session.findAll({
      where: dateFilter
    });

    const orders = await Order.findAll({
      where: dateFilter
    });

    const summary = {
      totalRevenue: sessions.reduce((sum, s) => sum + parseFloat(s.total || 0), 0),
      sessionRevenue: sessions.reduce((sum, s) => sum + parseFloat(s.session_cost || 0), 0),
      orderRevenue: orders.reduce((sum, o) => sum + parseFloat(o.total || 0), 0),
      totalTax: sessions.reduce((sum, s) => sum + parseFloat(s.tax || 0), 0),
      totalServiceFee: sessions.reduce((sum, s) => sum + parseFloat(s.service_fee || 0), 0),
      totalDiscounts: sessions.reduce((sum, s) => sum + parseFloat(s.discount || 0), 0),
      netAmount: 0
    };

    summary.netAmount = summary.totalRevenue - summary.totalDiscounts;

    res.json({
      success: true,
      data: { summary }
    });
  } catch (error) {
    console.error('Get financial summary error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error'
    });
  }
});

// Export report data
router.get('/export/:type', auth, authorize('Admin', 'Manager'), async (req, res) => {
  try {
    const { type } = req.params;
    const { startDate, endDate, format = 'json' } = req.query;
    
    let data = {};
    
    switch (type) {
      case 'sessions':
        data = await Session.findAll({
          where: startDate && endDate ? {
            created_at: {
              [Op.gte]: new Date(startDate),
              [Op.lte]: new Date(endDate)
            }
          } : {},
          include: [{ model: Table, as: 'table' }]
        });
        break;
        
      case 'orders':
        data = await Order.findAll({
          where: startDate && endDate ? {
            created_at: {
              [Op.gte]: new Date(startDate),
              [Op.lte]: new Date(endDate)
            }
          } : {},
          include: [
            { model: Table, as: 'table' },
            { model: OrderItem, as: 'items' }
          ]
        });
        break;
        
      default:
        return res.status(400).json({
          success: false,
          message: 'Invalid report type'
        });
    }

    // For now, just return JSON. In production, you might want to support CSV, Excel, etc.
    res.json({
      success: true,
      data: { [type]: data }
    });
  } catch (error) {
    console.error('Export report error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error'
    });
  }
});

module.exports = router;