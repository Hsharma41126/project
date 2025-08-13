const { DataTypes } = require('sequelize');
const { sequelize } = require('../config/database');

const Order = sequelize.define('Order', {
  id: {
    type: DataTypes.INTEGER,
    primaryKey: true,
    autoIncrement: true
  },
  order_id: {
    type: DataTypes.STRING(50),
    allowNull: false,
    unique: true
  },
  table_id: {
    type: DataTypes.INTEGER,
    allowNull: false,
    references: {
      model: 'tables',
      key: 'id'
    }
  },
  table_number: {
    type: DataTypes.STRING(20),
    allowNull: false
  },
  customer_name: {
    type: DataTypes.STRING(100),
    allowNull: false
  },
  customer_phone: {
    type: DataTypes.STRING(20),
    allowNull: false
  },
  service_type: {
    type: DataTypes.ENUM('dine-in', 'takeaway'),
    defaultValue: 'dine-in'
  },
  order_type: {
    type: DataTypes.ENUM('food', 'drinks', 'games', 'mixed'),
    allowNull: false
  },
  status: {
    type: DataTypes.ENUM('pending', 'confirmed', 'preparing', 'ready', 'served', 'cancelled'),
    defaultValue: 'pending'
  },
  // Pricing
  subtotal: {
    type: DataTypes.DECIMAL(10, 2),
    allowNull: false,
    defaultValue: 0.00
  },
  tax: {
    type: DataTypes.DECIMAL(10, 2),
    allowNull: false,
    defaultValue: 0.00
  },
  discount: {
    type: DataTypes.DECIMAL(10, 2),
    defaultValue: 0.00
  },
  discount_type: {
    type: DataTypes.ENUM('percentage', 'fixed'),
    defaultValue: 'percentage'
  },
  total: {
    type: DataTypes.DECIMAL(10, 2),
    allowNull: false,
    defaultValue: 0.00
  },
  // Payment info
  payment_status: {
    type: DataTypes.ENUM('unpaid', 'paid', 'refunded'),
    defaultValue: 'unpaid'
  },
  payment_method: {
    type: DataTypes.ENUM('cash', 'card', 'upi', 'online'),
    allowNull: true
  },
  // KOT info
  kot_printed: {
    type: DataTypes.BOOLEAN,
    defaultValue: false
  },
  kot_printed_at: {
    type: DataTypes.DATE,
    allowNull: true
  },
  // Staff who created the order
  created_by: {
    type: DataTypes.INTEGER,
    allowNull: false,
    references: {
      model: 'users',
      key: 'id'
    }
  },
  special_instructions: {
    type: DataTypes.TEXT,
    allowNull: true
  },
  estimated_time: {
    type: DataTypes.INTEGER,
    defaultValue: 30,
    comment: 'Estimated time in minutes'
  },
  actual_time: {
    type: DataTypes.INTEGER,
    allowNull: true,
    comment: 'Actual time in minutes'
  }
}, {
  tableName: 'orders',
  hooks: {
    beforeCreate: async (order) => {
      if (!order.order_id) {
        const date = new Date();
        const year = date.getFullYear();
        const month = String(date.getMonth() + 1).padStart(2, '0');
        const day = String(date.getDate()).padStart(2, '0');
        const random = Math.floor(Math.random() * 10000).toString().padStart(4, '0');
        order.order_id = `ORD-${year}${month}${day}-${random}`;
      }
    }
  }
});

module.exports = Order;